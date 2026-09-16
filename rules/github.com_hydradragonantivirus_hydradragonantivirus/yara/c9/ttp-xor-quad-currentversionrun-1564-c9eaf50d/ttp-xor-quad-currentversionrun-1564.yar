rule TTP_XOR_QUAD_CurrentVersionRun_1564 {
  strings:
    $key_1564 = { 46 0b [2] 62 05 [2] 49 29 [2] 67 0b [2] 73 10 [2] 7c 0a [2] 62 17 [2] 60 16 [2] 7b 10 [2] 67 17 [2] 7b 38 }

  condition:
    any of them
}