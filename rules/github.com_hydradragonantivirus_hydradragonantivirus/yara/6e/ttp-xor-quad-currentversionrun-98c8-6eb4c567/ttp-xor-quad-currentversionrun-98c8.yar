rule TTP_XOR_QUAD_CurrentVersionRun_98c8 {
  strings:
    $key_98c8 = { cb a7 [2] ef a9 [2] c4 85 [2] ea a7 [2] fe bc [2] f1 a6 [2] ef bb [2] ed ba [2] f6 bc [2] ea bb [2] f6 94 }

  condition:
    any of them
}