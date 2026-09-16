rule TTP_XOR_QUAD_CurrentVersionRun_e972 {
  strings:
    $key_e972 = { ba 1d [2] 9e 13 [2] b5 3f [2] 9b 1d [2] 8f 06 [2] 80 1c [2] 9e 01 [2] 9c 00 [2] 87 06 [2] 9b 01 [2] 87 2e }

  condition:
    any of them
}