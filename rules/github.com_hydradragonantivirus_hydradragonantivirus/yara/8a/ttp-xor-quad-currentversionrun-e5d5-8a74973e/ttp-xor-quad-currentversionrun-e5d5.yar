rule TTP_XOR_QUAD_CurrentVersionRun_e5d5 {
  strings:
    $key_e5d5 = { b6 ba [2] 92 b4 [2] b9 98 [2] 97 ba [2] 83 a1 [2] 8c bb [2] 92 a6 [2] 90 a7 [2] 8b a1 [2] 97 a6 [2] 8b 89 }

  condition:
    any of them
}