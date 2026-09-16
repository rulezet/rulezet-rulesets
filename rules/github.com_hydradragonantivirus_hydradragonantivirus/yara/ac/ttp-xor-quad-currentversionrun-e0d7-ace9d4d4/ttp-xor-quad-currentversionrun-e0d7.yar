rule TTP_XOR_QUAD_CurrentVersionRun_e0d7 {
  strings:
    $key_e0d7 = { b3 b8 [2] 97 b6 [2] bc 9a [2] 92 b8 [2] 86 a3 [2] 89 b9 [2] 97 a4 [2] 95 a5 [2] 8e a3 [2] 92 a4 [2] 8e 8b }

  condition:
    any of them
}