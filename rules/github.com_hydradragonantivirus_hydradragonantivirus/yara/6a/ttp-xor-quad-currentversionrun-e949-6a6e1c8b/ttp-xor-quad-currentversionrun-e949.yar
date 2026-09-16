rule TTP_XOR_QUAD_CurrentVersionRun_e949 {
  strings:
    $key_e949 = { ba 26 [2] 9e 28 [2] b5 04 [2] 9b 26 [2] 8f 3d [2] 80 27 [2] 9e 3a [2] 9c 3b [2] 87 3d [2] 9b 3a [2] 87 15 }

  condition:
    any of them
}