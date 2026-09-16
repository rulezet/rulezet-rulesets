rule TTP_XOR_QUAD_CurrentVersionRun_e019 {
  strings:
    $key_e019 = { b3 76 [2] 97 78 [2] bc 54 [2] 92 76 [2] 86 6d [2] 89 77 [2] 97 6a [2] 95 6b [2] 8e 6d [2] 92 6a [2] 8e 45 }

  condition:
    any of them
}