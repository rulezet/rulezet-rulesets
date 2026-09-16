rule TTP_XOR_QUAD_CurrentVersionRun_1264 {
  strings:
    $key_1264 = { 41 0b [2] 65 05 [2] 4e 29 [2] 60 0b [2] 74 10 [2] 7b 0a [2] 65 17 [2] 67 16 [2] 7c 10 [2] 60 17 [2] 7c 38 }

  condition:
    any of them
}