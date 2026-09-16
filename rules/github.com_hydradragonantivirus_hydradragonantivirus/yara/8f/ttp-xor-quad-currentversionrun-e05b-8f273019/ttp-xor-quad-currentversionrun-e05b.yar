rule TTP_XOR_QUAD_CurrentVersionRun_e05b {
  strings:
    $key_e05b = { b3 34 [2] 97 3a [2] bc 16 [2] 92 34 [2] 86 2f [2] 89 35 [2] 97 28 [2] 95 29 [2] 8e 2f [2] 92 28 [2] 8e 07 }

  condition:
    any of them
}