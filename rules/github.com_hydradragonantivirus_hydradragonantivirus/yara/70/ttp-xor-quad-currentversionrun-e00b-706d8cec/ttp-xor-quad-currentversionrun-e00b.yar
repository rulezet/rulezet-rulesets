rule TTP_XOR_QUAD_CurrentVersionRun_e00b {
  strings:
    $key_e00b = { b3 64 [2] 97 6a [2] bc 46 [2] 92 64 [2] 86 7f [2] 89 65 [2] 97 78 [2] 95 79 [2] 8e 7f [2] 92 78 [2] 8e 57 }

  condition:
    any of them
}