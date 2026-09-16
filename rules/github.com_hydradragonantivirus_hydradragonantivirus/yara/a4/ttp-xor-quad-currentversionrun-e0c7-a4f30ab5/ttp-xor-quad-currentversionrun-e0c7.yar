rule TTP_XOR_QUAD_CurrentVersionRun_e0c7 {
  strings:
    $key_e0c7 = { b3 a8 [2] 97 a6 [2] bc 8a [2] 92 a8 [2] 86 b3 [2] 89 a9 [2] 97 b4 [2] 95 b5 [2] 8e b3 [2] 92 b4 [2] 8e 9b }

  condition:
    any of them
}