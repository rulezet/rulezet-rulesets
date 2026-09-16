rule TTP_XOR_QUAD_CurrentVersionRun_e06b {
  strings:
    $key_e06b = { b3 04 [2] 97 0a [2] bc 26 [2] 92 04 [2] 86 1f [2] 89 05 [2] 97 18 [2] 95 19 [2] 8e 1f [2] 92 18 [2] 8e 37 }

  condition:
    any of them
}