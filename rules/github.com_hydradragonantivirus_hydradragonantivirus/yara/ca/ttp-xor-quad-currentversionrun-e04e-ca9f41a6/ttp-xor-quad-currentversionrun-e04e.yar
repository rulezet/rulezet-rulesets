rule TTP_XOR_QUAD_CurrentVersionRun_e04e {
  strings:
    $key_e04e = { b3 21 [2] 97 2f [2] bc 03 [2] 92 21 [2] 86 3a [2] 89 20 [2] 97 3d [2] 95 3c [2] 8e 3a [2] 92 3d [2] 8e 12 }

  condition:
    any of them
}