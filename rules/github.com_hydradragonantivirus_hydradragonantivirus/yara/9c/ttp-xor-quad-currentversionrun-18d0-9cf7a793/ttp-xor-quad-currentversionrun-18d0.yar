rule TTP_XOR_QUAD_CurrentVersionRun_18d0 {
  strings:
    $key_18d0 = { 4b bf [2] 6f b1 [2] 44 9d [2] 6a bf [2] 7e a4 [2] 71 be [2] 6f a3 [2] 6d a2 [2] 76 a4 [2] 6a a3 [2] 76 8c }

  condition:
    any of them
}