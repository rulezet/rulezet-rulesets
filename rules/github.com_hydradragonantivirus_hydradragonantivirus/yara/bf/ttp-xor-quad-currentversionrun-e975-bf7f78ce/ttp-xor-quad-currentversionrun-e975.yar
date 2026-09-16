rule TTP_XOR_QUAD_CurrentVersionRun_e975 {
  strings:
    $key_e975 = { ba 1a [2] 9e 14 [2] b5 38 [2] 9b 1a [2] 8f 01 [2] 80 1b [2] 9e 06 [2] 9c 07 [2] 87 01 [2] 9b 06 [2] 87 29 }

  condition:
    any of them
}