rule TTP_XOR_QUAD_CurrentVersionRun_7008 {
  strings:
    $key_7008 = { 23 67 [2] 07 69 [2] 2c 45 [2] 02 67 [2] 16 7c [2] 19 66 [2] 07 7b [2] 05 7a [2] 1e 7c [2] 02 7b [2] 1e 54 }

  condition:
    any of them
}