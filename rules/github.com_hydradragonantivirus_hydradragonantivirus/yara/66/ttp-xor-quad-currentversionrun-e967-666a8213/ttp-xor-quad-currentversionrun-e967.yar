rule TTP_XOR_QUAD_CurrentVersionRun_e967 {
  strings:
    $key_e967 = { ba 08 [2] 9e 06 [2] b5 2a [2] 9b 08 [2] 8f 13 [2] 80 09 [2] 9e 14 [2] 9c 15 [2] 87 13 [2] 9b 14 [2] 87 3b }

  condition:
    any of them
}