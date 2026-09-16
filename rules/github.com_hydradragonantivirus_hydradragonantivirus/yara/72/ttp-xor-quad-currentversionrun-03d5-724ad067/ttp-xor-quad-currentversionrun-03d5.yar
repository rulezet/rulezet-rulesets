rule TTP_XOR_QUAD_CurrentVersionRun_03d5 {
  strings:
    $key_03d5 = { 50 ba [2] 74 b4 [2] 5f 98 [2] 71 ba [2] 65 a1 [2] 6a bb [2] 74 a6 [2] 76 a7 [2] 6d a1 [2] 71 a6 [2] 6d 89 }

  condition:
    any of them
}