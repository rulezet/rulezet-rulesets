rule TTP_XOR_QUAD_CurrentVersionRun_e917 {
  strings:
    $key_e917 = { ba 78 [2] 9e 76 [2] b5 5a [2] 9b 78 [2] 8f 63 [2] 80 79 [2] 9e 64 [2] 9c 65 [2] 87 63 [2] 9b 64 [2] 87 4b }

  condition:
    any of them
}