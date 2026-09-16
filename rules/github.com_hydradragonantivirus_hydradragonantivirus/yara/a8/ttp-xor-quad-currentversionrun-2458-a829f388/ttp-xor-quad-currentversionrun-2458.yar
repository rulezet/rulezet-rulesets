rule TTP_XOR_QUAD_CurrentVersionRun_2458 {
  strings:
    $key_2458 = { 77 37 [2] 53 39 [2] 78 15 [2] 56 37 [2] 42 2c [2] 4d 36 [2] 53 2b [2] 51 2a [2] 4a 2c [2] 56 2b [2] 4a 04 }

  condition:
    any of them
}