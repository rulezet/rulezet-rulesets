rule TTP_XOR_QUAD_CurrentVersionRun_e955 {
  strings:
    $key_e955 = { ba 3a [2] 9e 34 [2] b5 18 [2] 9b 3a [2] 8f 21 [2] 80 3b [2] 9e 26 [2] 9c 27 [2] 87 21 [2] 9b 26 [2] 87 09 }

  condition:
    any of them
}