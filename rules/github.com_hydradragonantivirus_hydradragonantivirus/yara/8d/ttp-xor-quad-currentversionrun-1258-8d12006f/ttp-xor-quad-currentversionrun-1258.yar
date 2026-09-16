rule TTP_XOR_QUAD_CurrentVersionRun_1258 {
  strings:
    $key_1258 = { 41 37 [2] 65 39 [2] 4e 15 [2] 60 37 [2] 74 2c [2] 7b 36 [2] 65 2b [2] 67 2a [2] 7c 2c [2] 60 2b [2] 7c 04 }

  condition:
    any of them
}