rule TTP_XOR_QUAD_CurrentVersionRun_1257 {
  strings:
    $key_1257 = { 41 38 [2] 65 36 [2] 4e 1a [2] 60 38 [2] 74 23 [2] 7b 39 [2] 65 24 [2] 67 25 [2] 7c 23 [2] 60 24 [2] 7c 0b }

  condition:
    any of them
}