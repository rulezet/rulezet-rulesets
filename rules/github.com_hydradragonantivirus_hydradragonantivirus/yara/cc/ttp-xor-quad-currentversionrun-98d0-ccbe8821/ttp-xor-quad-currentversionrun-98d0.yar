rule TTP_XOR_QUAD_CurrentVersionRun_98d0 {
  strings:
    $key_98d0 = { cb bf [2] ef b1 [2] c4 9d [2] ea bf [2] fe a4 [2] f1 be [2] ef a3 [2] ed a2 [2] f6 a4 [2] ea a3 [2] f6 8c }

  condition:
    any of them
}