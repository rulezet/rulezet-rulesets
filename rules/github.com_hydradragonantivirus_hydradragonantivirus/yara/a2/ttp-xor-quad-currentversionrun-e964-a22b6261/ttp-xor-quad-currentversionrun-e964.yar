rule TTP_XOR_QUAD_CurrentVersionRun_e964 {
  strings:
    $key_e964 = { ba 0b [2] 9e 05 [2] b5 29 [2] 9b 0b [2] 8f 10 [2] 80 0a [2] 9e 17 [2] 9c 16 [2] 87 10 [2] 9b 17 [2] 87 38 }

  condition:
    any of them
}