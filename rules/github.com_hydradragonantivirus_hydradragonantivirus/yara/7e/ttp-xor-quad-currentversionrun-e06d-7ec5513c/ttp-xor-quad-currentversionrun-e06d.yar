rule TTP_XOR_QUAD_CurrentVersionRun_e06d {
  strings:
    $key_e06d = { b3 02 [2] 97 0c [2] bc 20 [2] 92 02 [2] 86 19 [2] 89 03 [2] 97 1e [2] 95 1f [2] 8e 19 [2] 92 1e [2] 8e 31 }

  condition:
    any of them
}