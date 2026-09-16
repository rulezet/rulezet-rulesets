rule TTP_XOR_QUAD_CurrentVersionRun_5935 {
  strings:
    $key_5935 = { 0a 5a [2] 2e 54 [2] 05 78 [2] 2b 5a [2] 3f 41 [2] 30 5b [2] 2e 46 [2] 2c 47 [2] 37 41 [2] 2b 46 [2] 37 69 }

  condition:
    any of them
}