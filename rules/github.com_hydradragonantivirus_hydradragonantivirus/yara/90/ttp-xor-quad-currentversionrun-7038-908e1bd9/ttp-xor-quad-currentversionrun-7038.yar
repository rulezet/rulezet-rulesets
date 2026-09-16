rule TTP_XOR_QUAD_CurrentVersionRun_7038 {
  strings:
    $key_7038 = { 23 57 [2] 07 59 [2] 2c 75 [2] 02 57 [2] 16 4c [2] 19 56 [2] 07 4b [2] 05 4a [2] 1e 4c [2] 02 4b [2] 1e 64 }

  condition:
    any of them
}