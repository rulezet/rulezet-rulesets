rule TTP_XOR_QUAD_CurrentVersionRun_e919 {
  strings:
    $key_e919 = { ba 76 [2] 9e 78 [2] b5 54 [2] 9b 76 [2] 8f 6d [2] 80 77 [2] 9e 6a [2] 9c 6b [2] 87 6d [2] 9b 6a [2] 87 45 }

  condition:
    any of them
}