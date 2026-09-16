rule TTP_XOR_QUAD_CurrentVersionRun_3958 {
  strings:
    $key_3958 = { 6a 37 [2] 4e 39 [2] 65 15 [2] 4b 37 [2] 5f 2c [2] 50 36 [2] 4e 2b [2] 4c 2a [2] 57 2c [2] 4b 2b [2] 57 04 }

  condition:
    any of them
}