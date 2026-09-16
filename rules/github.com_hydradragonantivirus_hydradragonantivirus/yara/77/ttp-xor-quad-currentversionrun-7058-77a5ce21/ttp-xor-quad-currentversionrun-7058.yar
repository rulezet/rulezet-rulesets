rule TTP_XOR_QUAD_CurrentVersionRun_7058 {
  strings:
    $key_7058 = { 23 37 [2] 07 39 [2] 2c 15 [2] 02 37 [2] 16 2c [2] 19 36 [2] 07 2b [2] 05 2a [2] 1e 2c [2] 02 2b [2] 1e 04 }

  condition:
    any of them
}