rule TTP_XOR_QUAD_CurrentVersionRun_08d0 {
  strings:
    $key_08d0 = { 5b bf [2] 7f b1 [2] 54 9d [2] 7a bf [2] 6e a4 [2] 61 be [2] 7f a3 [2] 7d a2 [2] 66 a4 [2] 7a a3 [2] 66 8c }

  condition:
    any of them
}