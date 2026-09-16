rule TTP_XOR_QUAD_CurrentVersionRun_6b58 {
  strings:
    $key_6b58 = { 38 37 [2] 1c 39 [2] 37 15 [2] 19 37 [2] 0d 2c [2] 02 36 [2] 1c 2b [2] 1e 2a [2] 05 2c [2] 19 2b [2] 05 04 }

  condition:
    any of them
}