rule TTP_XOR_QUAD_CurrentVersionRun_e944 {
  strings:
    $key_e944 = { ba 2b [2] 9e 25 [2] b5 09 [2] 9b 2b [2] 8f 30 [2] 80 2a [2] 9e 37 [2] 9c 36 [2] 87 30 [2] 9b 37 [2] 87 18 }

  condition:
    any of them
}