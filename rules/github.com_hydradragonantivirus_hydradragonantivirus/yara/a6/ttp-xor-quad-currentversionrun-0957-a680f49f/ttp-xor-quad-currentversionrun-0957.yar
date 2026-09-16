rule TTP_XOR_QUAD_CurrentVersionRun_0957 {
  strings:
    $key_0957 = { 5a 38 [2] 7e 36 [2] 55 1a [2] 7b 38 [2] 6f 23 [2] 60 39 [2] 7e 24 [2] 7c 25 [2] 67 23 [2] 7b 24 [2] 67 0b }

  condition:
    any of them
}