rule TTP_XOR_QUAD_CurrentVersionRun_5928 {
  strings:
    $key_5928 = { 0a 47 [2] 2e 49 [2] 05 65 [2] 2b 47 [2] 3f 5c [2] 30 46 [2] 2e 5b [2] 2c 5a [2] 37 5c [2] 2b 5b [2] 37 74 }

  condition:
    any of them
}