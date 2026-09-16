rule TTP_XOR_QUAD_CurrentVersionRun_e04c {
  strings:
    $key_e04c = { b3 23 [2] 97 2d [2] bc 01 [2] 92 23 [2] 86 38 [2] 89 22 [2] 97 3f [2] 95 3e [2] 8e 38 [2] 92 3f [2] 8e 10 }

  condition:
    any of them
}