rule TTP_XOR_QUAD_CurrentVersionRun_e958 {
  strings:
    $key_e958 = { ba 37 [2] 9e 39 [2] b5 15 [2] 9b 37 [2] 8f 2c [2] 80 36 [2] 9e 2b [2] 9c 2a [2] 87 2c [2] 9b 2b [2] 87 04 }

  condition:
    any of them
}