rule TTP_XOR_QUAD_CurrentVersionRun_596e {
  strings:
    $key_596e = { 0a 01 [2] 2e 0f [2] 05 23 [2] 2b 01 [2] 3f 1a [2] 30 00 [2] 2e 1d [2] 2c 1c [2] 37 1a [2] 2b 1d [2] 37 32 }

  condition:
    any of them
}