rule TTP_XOR_QUAD_CurrentVersionRun_7039 {
  strings:
    $key_7039 = { 23 56 [2] 07 58 [2] 2c 74 [2] 02 56 [2] 16 4d [2] 19 57 [2] 07 4a [2] 05 4b [2] 1e 4d [2] 02 4a [2] 1e 65 }

  condition:
    any of them
}