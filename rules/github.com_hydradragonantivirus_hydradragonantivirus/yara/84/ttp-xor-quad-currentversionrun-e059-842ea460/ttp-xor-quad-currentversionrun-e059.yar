rule TTP_XOR_QUAD_CurrentVersionRun_e059 {
  strings:
    $key_e059 = { b3 36 [2] 97 38 [2] bc 14 [2] 92 36 [2] 86 2d [2] 89 37 [2] 97 2a [2] 95 2b [2] 8e 2d [2] 92 2a [2] 8e 05 }

  condition:
    any of them
}