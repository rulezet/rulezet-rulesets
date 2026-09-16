rule TTP_XOR_QUAD_CurrentVersionRun_e01a {
  strings:
    $key_e01a = { b3 75 [2] 97 7b [2] bc 57 [2] 92 75 [2] 86 6e [2] 89 74 [2] 97 69 [2] 95 68 [2] 8e 6e [2] 92 69 [2] 8e 46 }

  condition:
    any of them
}