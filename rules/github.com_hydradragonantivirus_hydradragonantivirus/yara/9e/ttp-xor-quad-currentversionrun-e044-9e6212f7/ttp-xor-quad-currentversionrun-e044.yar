rule TTP_XOR_QUAD_CurrentVersionRun_e044 {
  strings:
    $key_e044 = { b3 2b [2] 97 25 [2] bc 09 [2] 92 2b [2] 86 30 [2] 89 2a [2] 97 37 [2] 95 36 [2] 8e 30 [2] 92 37 [2] 8e 18 }

  condition:
    any of them
}