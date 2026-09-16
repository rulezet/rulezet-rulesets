rule TTP_XOR_QUAD_CurrentVersionRun_e07d {
  strings:
    $key_e07d = { b3 12 [2] 97 1c [2] bc 30 [2] 92 12 [2] 86 09 [2] 89 13 [2] 97 0e [2] 95 0f [2] 8e 09 [2] 92 0e [2] 8e 21 }

  condition:
    any of them
}