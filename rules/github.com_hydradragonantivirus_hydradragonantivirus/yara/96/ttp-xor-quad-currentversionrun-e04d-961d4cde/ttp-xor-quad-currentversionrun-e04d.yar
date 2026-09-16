rule TTP_XOR_QUAD_CurrentVersionRun_e04d {
  strings:
    $key_e04d = { b3 22 [2] 97 2c [2] bc 00 [2] 92 22 [2] 86 39 [2] 89 23 [2] 97 3e [2] 95 3f [2] 8e 39 [2] 92 3e [2] 8e 11 }

  condition:
    any of them
}