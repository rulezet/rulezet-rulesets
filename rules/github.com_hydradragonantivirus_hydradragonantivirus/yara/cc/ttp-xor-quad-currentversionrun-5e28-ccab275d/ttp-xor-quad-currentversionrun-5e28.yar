rule TTP_XOR_QUAD_CurrentVersionRun_5e28 {
  strings:
    $key_5e28 = { 0d 47 [2] 29 49 [2] 02 65 [2] 2c 47 [2] 38 5c [2] 37 46 [2] 29 5b [2] 2b 5a [2] 30 5c [2] 2c 5b [2] 30 74 }

  condition:
    any of them
}