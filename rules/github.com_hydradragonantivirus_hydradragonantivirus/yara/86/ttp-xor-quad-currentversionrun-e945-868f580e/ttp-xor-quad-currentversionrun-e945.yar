rule TTP_XOR_QUAD_CurrentVersionRun_e945 {
  strings:
    $key_e945 = { ba 2a [2] 9e 24 [2] b5 08 [2] 9b 2a [2] 8f 31 [2] 80 2b [2] 9e 36 [2] 9c 37 [2] 87 31 [2] 9b 36 [2] 87 19 }

  condition:
    any of them
}