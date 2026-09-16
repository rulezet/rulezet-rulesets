rule TTP_XOR_QUAD_CurrentVersionRun_e939 {
  strings:
    $key_e939 = { ba 56 [2] 9e 58 [2] b5 74 [2] 9b 56 [2] 8f 4d [2] 80 57 [2] 9e 4a [2] 9c 4b [2] 87 4d [2] 9b 4a [2] 87 65 }

  condition:
    any of them
}