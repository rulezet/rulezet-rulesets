rule TTP_XOR_QUAD_CurrentVersionRun_2958 {
  strings:
    $key_2958 = { 7a 37 [2] 5e 39 [2] 75 15 [2] 5b 37 [2] 4f 2c [2] 40 36 [2] 5e 2b [2] 5c 2a [2] 47 2c [2] 5b 2b [2] 47 04 }

  condition:
    any of them
}