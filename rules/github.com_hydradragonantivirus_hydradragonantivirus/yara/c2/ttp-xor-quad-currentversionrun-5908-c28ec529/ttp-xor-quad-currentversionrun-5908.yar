rule TTP_XOR_QUAD_CurrentVersionRun_5908 {
  strings:
    $key_5908 = { 0a 67 [2] 2e 69 [2] 05 45 [2] 2b 67 [2] 3f 7c [2] 30 66 [2] 2e 7b [2] 2c 7a [2] 37 7c [2] 2b 7b [2] 37 54 }

  condition:
    any of them
}