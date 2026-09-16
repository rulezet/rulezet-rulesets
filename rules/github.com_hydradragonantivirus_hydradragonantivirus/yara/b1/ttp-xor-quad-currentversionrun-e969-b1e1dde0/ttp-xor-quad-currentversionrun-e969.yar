rule TTP_XOR_QUAD_CurrentVersionRun_e969 {
  strings:
    $key_e969 = { ba 06 [2] 9e 08 [2] b5 24 [2] 9b 06 [2] 8f 1d [2] 80 07 [2] 9e 1a [2] 9c 1b [2] 87 1d [2] 9b 1a [2] 87 35 }

  condition:
    any of them
}