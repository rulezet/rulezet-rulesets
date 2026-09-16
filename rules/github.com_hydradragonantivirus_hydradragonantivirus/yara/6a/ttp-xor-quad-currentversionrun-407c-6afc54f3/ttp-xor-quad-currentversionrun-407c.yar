rule TTP_XOR_QUAD_CurrentVersionRun_407c {
  strings:
    $key_407c = { 13 13 [2] 37 1d [2] 1c 31 [2] 32 13 [2] 26 08 [2] 29 12 [2] 37 0f [2] 35 0e [2] 2e 08 [2] 32 0f [2] 2e 20 }

  condition:
    any of them
}