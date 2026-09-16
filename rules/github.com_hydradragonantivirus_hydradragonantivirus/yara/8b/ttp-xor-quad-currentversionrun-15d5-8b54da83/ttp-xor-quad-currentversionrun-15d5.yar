rule TTP_XOR_QUAD_CurrentVersionRun_15d5 {
  strings:
    $key_15d5 = { 46 ba [2] 62 b4 [2] 49 98 [2] 67 ba [2] 73 a1 [2] 7c bb [2] 62 a6 [2] 60 a7 [2] 7b a1 [2] 67 a6 [2] 7b 89 }

  condition:
    any of them
}