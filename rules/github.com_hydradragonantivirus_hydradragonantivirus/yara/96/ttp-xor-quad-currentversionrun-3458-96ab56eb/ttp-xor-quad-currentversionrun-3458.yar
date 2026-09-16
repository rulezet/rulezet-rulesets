rule TTP_XOR_QUAD_CurrentVersionRun_3458 {
  strings:
    $key_3458 = { 67 37 [2] 43 39 [2] 68 15 [2] 46 37 [2] 52 2c [2] 5d 36 [2] 43 2b [2] 41 2a [2] 5a 2c [2] 46 2b [2] 5a 04 }

  condition:
    any of them
}