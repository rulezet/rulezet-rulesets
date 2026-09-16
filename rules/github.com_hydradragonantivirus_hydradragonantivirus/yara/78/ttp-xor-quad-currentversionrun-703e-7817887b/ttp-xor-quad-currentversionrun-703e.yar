rule TTP_XOR_QUAD_CurrentVersionRun_703e {
  strings:
    $key_703e = { 23 51 [2] 07 5f [2] 2c 73 [2] 02 51 [2] 16 4a [2] 19 50 [2] 07 4d [2] 05 4c [2] 1e 4a [2] 02 4d [2] 1e 62 }

  condition:
    any of them
}