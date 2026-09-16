rule TTP_XOR_QUAD_CurrentVersionRun_98d5 {
  strings:
    $key_98d5 = { cb ba [2] ef b4 [2] c4 98 [2] ea ba [2] fe a1 [2] f1 bb [2] ef a6 [2] ed a7 [2] f6 a1 [2] ea a6 [2] f6 89 }

  condition:
    any of them
}