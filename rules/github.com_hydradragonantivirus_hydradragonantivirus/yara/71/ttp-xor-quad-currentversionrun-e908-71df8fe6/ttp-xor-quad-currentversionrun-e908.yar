rule TTP_XOR_QUAD_CurrentVersionRun_e908 {
  strings:
    $key_e908 = { ba 67 [2] 9e 69 [2] b5 45 [2] 9b 67 [2] 8f 7c [2] 80 66 [2] 9e 7b [2] 9c 7a [2] 87 7c [2] 9b 7b [2] 87 54 }

  condition:
    any of them
}