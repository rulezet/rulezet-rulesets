rule TTP_XOR_QUAD_CurrentVersionRun_e06a {
  strings:
    $key_e06a = { b3 05 [2] 97 0b [2] bc 27 [2] 92 05 [2] 86 1e [2] 89 04 [2] 97 19 [2] 95 18 [2] 8e 1e [2] 92 19 [2] 8e 36 }

  condition:
    any of them
}