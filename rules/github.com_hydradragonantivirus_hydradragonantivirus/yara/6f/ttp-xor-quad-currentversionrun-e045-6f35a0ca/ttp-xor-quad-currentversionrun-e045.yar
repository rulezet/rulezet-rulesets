rule TTP_XOR_QUAD_CurrentVersionRun_e045 {
  strings:
    $key_e045 = { b3 2a [2] 97 24 [2] bc 08 [2] 92 2a [2] 86 31 [2] 89 2b [2] 97 36 [2] 95 37 [2] 8e 31 [2] 92 36 [2] 8e 19 }

  condition:
    any of them
}