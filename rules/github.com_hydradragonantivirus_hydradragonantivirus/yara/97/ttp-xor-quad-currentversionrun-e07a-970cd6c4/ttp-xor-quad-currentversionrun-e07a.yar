rule TTP_XOR_QUAD_CurrentVersionRun_e07a {
  strings:
    $key_e07a = { b3 15 [2] 97 1b [2] bc 37 [2] 92 15 [2] 86 0e [2] 89 14 [2] 97 09 [2] 95 08 [2] 8e 0e [2] 92 09 [2] 8e 26 }

  condition:
    any of them
}