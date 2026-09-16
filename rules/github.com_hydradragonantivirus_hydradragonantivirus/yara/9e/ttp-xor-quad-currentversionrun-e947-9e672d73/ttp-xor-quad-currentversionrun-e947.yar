rule TTP_XOR_QUAD_CurrentVersionRun_e947 {
  strings:
    $key_e947 = { ba 28 [2] 9e 26 [2] b5 0a [2] 9b 28 [2] 8f 33 [2] 80 29 [2] 9e 34 [2] 9c 35 [2] 87 33 [2] 9b 34 [2] 87 1b }

  condition:
    any of them
}