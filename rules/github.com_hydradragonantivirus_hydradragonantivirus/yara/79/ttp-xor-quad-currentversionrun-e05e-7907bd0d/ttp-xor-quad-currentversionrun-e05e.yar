rule TTP_XOR_QUAD_CurrentVersionRun_e05e {
  strings:
    $key_e05e = { b3 31 [2] 97 3f [2] bc 13 [2] 92 31 [2] 86 2a [2] 89 30 [2] 97 2d [2] 95 2c [2] 8e 2a [2] 92 2d [2] 8e 02 }

  condition:
    any of them
}