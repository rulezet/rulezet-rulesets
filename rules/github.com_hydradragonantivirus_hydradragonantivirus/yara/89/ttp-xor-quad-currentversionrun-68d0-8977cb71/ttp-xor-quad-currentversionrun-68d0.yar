rule TTP_XOR_QUAD_CurrentVersionRun_68d0 {
  strings:
    $key_68d0 = { 3b bf [2] 1f b1 [2] 34 9d [2] 1a bf [2] 0e a4 [2] 01 be [2] 1f a3 [2] 1d a2 [2] 06 a4 [2] 1a a3 [2] 06 8c }

  condition:
    any of them
}