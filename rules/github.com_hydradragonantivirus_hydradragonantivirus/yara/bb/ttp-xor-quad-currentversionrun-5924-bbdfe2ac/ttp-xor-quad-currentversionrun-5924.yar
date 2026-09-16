rule TTP_XOR_QUAD_CurrentVersionRun_5924 {
  strings:
    $key_5924 = { 0a 4b [2] 2e 45 [2] 05 69 [2] 2b 4b [2] 3f 50 [2] 30 4a [2] 2e 57 [2] 2c 56 [2] 37 50 [2] 2b 57 [2] 37 78 }

  condition:
    any of them
}