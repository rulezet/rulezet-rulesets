rule TTP_XOR_QUAD_CurrentVersionRun_e956 {
  strings:
    $key_e956 = { ba 39 [2] 9e 37 [2] b5 1b [2] 9b 39 [2] 8f 22 [2] 80 38 [2] 9e 25 [2] 9c 24 [2] 87 22 [2] 9b 25 [2] 87 0a }

  condition:
    any of them
}