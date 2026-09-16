rule TTP_XOR_QUAD_CurrentVersionRun_e055 {
  strings:
    $key_e055 = { b3 3a [2] 97 34 [2] bc 18 [2] 92 3a [2] 86 21 [2] 89 3b [2] 97 26 [2] 95 27 [2] 8e 21 [2] 92 26 [2] 8e 09 }

  condition:
    any of them
}