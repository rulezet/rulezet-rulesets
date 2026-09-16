rule TTP_XOR_QUAD_CurrentVersionRun_4b58 {
  strings:
    $key_4b58 = { 18 37 [2] 3c 39 [2] 17 15 [2] 39 37 [2] 2d 2c [2] 22 36 [2] 3c 2b [2] 3e 2a [2] 25 2c [2] 39 2b [2] 25 04 }

  condition:
    any of them
}