rule TTP_XOR_QUAD_CurrentVersionRun_5939 {
  strings:
    $key_5939 = { 0a 56 [2] 2e 58 [2] 05 74 [2] 2b 56 [2] 3f 4d [2] 30 57 [2] 2e 4a [2] 2c 4b [2] 37 4d [2] 2b 4a [2] 37 65 }

  condition:
    any of them
}