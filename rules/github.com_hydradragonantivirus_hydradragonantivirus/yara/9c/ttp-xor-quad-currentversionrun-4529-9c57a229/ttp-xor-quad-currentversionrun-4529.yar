rule TTP_XOR_QUAD_CurrentVersionRun_4529 {
  strings:
    $key_4529 = { 16 46 [2] 32 48 [2] 19 64 [2] 37 46 [2] 23 5d [2] 2c 47 [2] 32 5a [2] 30 5b [2] 2b 5d [2] 37 5a [2] 2b 75 }

  condition:
    any of them
}