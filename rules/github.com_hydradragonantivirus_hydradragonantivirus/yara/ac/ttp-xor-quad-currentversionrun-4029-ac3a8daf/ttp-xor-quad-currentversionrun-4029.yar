rule TTP_XOR_QUAD_CurrentVersionRun_4029 {
  strings:
    $key_4029 = { 13 46 [2] 37 48 [2] 1c 64 [2] 32 46 [2] 26 5d [2] 29 47 [2] 37 5a [2] 35 5b [2] 2e 5d [2] 32 5a [2] 2e 75 }

  condition:
    any of them
}