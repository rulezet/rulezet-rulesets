rule TTP_XOR_QUAD_CurrentVersionRun_5915 {
  strings:
    $key_5915 = { 0a 7a [2] 2e 74 [2] 05 58 [2] 2b 7a [2] 3f 61 [2] 30 7b [2] 2e 66 [2] 2c 67 [2] 37 61 [2] 2b 66 [2] 37 49 }

  condition:
    any of them
}