rule TTP_XOR_QUAD_CurrentVersionRun_5925 {
  strings:
    $key_5925 = { 0a 4a [2] 2e 44 [2] 05 68 [2] 2b 4a [2] 3f 51 [2] 30 4b [2] 2e 56 [2] 2c 57 [2] 37 51 [2] 2b 56 [2] 37 79 }

  condition:
    any of them
}