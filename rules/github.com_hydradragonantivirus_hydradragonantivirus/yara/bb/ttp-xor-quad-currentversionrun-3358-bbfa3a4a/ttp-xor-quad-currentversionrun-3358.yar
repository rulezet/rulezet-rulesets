rule TTP_XOR_QUAD_CurrentVersionRun_3358 {
  strings:
    $key_3358 = { 60 37 [2] 44 39 [2] 6f 15 [2] 41 37 [2] 55 2c [2] 5a 36 [2] 44 2b [2] 46 2a [2] 5d 2c [2] 41 2b [2] 5d 04 }

  condition:
    any of them
}