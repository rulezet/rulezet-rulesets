rule TTP_XOR_QUAD_CurrentVersionRun_e925 {
  strings:
    $key_e925 = { ba 4a [2] 9e 44 [2] b5 68 [2] 9b 4a [2] 8f 51 [2] 80 4b [2] 9e 56 [2] 9c 57 [2] 87 51 [2] 9b 56 [2] 87 79 }

  condition:
    any of them
}