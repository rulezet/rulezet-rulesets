rule TTP_XOR_QUAD_CurrentVersionRun_e024 {
  strings:
    $key_e024 = { b3 4b [2] 97 45 [2] bc 69 [2] 92 4b [2] 86 50 [2] 89 4a [2] 97 57 [2] 95 56 [2] 8e 50 [2] 92 57 [2] 8e 78 }

  condition:
    any of them
}