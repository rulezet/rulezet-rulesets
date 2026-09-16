rule TTP_XOR_QUAD_CurrentVersionRun_e957 {
  strings:
    $key_e957 = { ba 38 [2] 9e 36 [2] b5 1a [2] 9b 38 [2] 8f 23 [2] 80 39 [2] 9e 24 [2] 9c 25 [2] 87 23 [2] 9b 24 [2] 87 0b }

  condition:
    any of them
}