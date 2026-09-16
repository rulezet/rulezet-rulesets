rule TTP_XOR_QUAD_CurrentVersionRun_e905 {
  strings:
    $key_e905 = { ba 6a [2] 9e 64 [2] b5 48 [2] 9b 6a [2] 8f 71 [2] 80 6b [2] 9e 76 [2] 9c 77 [2] 87 71 [2] 9b 76 [2] 87 59 }

  condition:
    any of them
}