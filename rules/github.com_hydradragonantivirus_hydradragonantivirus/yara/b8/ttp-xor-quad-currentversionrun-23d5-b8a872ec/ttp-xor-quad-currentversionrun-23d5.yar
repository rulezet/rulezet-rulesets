rule TTP_XOR_QUAD_CurrentVersionRun_23d5 {
  strings:
    $key_23d5 = { 70 ba [2] 54 b4 [2] 7f 98 [2] 51 ba [2] 45 a1 [2] 4a bb [2] 54 a6 [2] 56 a7 [2] 4d a1 [2] 51 a6 [2] 4d 89 }

  condition:
    any of them
}