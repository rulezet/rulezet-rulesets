rule TTP_XOR_QUAD_CurrentVersionRun_27d5 {
  strings:
    $key_27d5 = { 74 ba [2] 50 b4 [2] 7b 98 [2] 55 ba [2] 41 a1 [2] 4e bb [2] 50 a6 [2] 52 a7 [2] 49 a1 [2] 55 a6 [2] 49 89 }

  condition:
    any of them
}