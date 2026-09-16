rule TTP_XOR_QUAD_CurrentVersionRun_98c9 {
  strings:
    $key_98c9 = { cb a6 [2] ef a8 [2] c4 84 [2] ea a6 [2] fe bd [2] f1 a7 [2] ef ba [2] ed bb [2] f6 bd [2] ea ba [2] f6 95 }

  condition:
    any of them
}