rule TTP_XOR_QUAD_CurrentVersionRun_5959 {
  strings:
    $key_5959 = { 0a 36 [2] 2e 38 [2] 05 14 [2] 2b 36 [2] 3f 2d [2] 30 37 [2] 2e 2a [2] 2c 2b [2] 37 2d [2] 2b 2a [2] 37 05 }

  condition:
    any of them
}