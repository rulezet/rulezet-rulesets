rule TTP_XOR_QUAD_CurrentVersionRun_e03e {
  strings:
    $key_e03e = { b3 51 [2] 97 5f [2] bc 73 [2] 92 51 [2] 86 4a [2] 89 50 [2] 97 4d [2] 95 4c [2] 8e 4a [2] 92 4d [2] 8e 62 }

  condition:
    any of them
}