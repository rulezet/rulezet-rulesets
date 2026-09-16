rule TTP_XOR_QUAD_CurrentVersionRun_403e {
  strings:
    $key_403e = { 13 51 [2] 37 5f [2] 1c 73 [2] 32 51 [2] 26 4a [2] 29 50 [2] 37 4d [2] 35 4c [2] 2e 4a [2] 32 4d [2] 2e 62 }

  condition:
    any of them
}