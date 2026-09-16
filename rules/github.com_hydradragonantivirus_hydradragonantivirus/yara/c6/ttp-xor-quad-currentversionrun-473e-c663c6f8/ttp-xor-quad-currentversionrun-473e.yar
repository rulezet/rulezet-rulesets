rule TTP_XOR_QUAD_CurrentVersionRun_473e {
  strings:
    $key_473e = { 14 51 [2] 30 5f [2] 1b 73 [2] 35 51 [2] 21 4a [2] 2e 50 [2] 30 4d [2] 32 4c [2] 29 4a [2] 35 4d [2] 29 62 }

  condition:
    any of them
}