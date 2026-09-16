rule TTP_XOR_QUAD_CurrentVersionRun_3558 {
  strings:
    $key_3558 = { 66 37 [2] 42 39 [2] 69 15 [2] 47 37 [2] 53 2c [2] 5c 36 [2] 42 2b [2] 40 2a [2] 5b 2c [2] 47 2b [2] 5b 04 }

  condition:
    any of them
}