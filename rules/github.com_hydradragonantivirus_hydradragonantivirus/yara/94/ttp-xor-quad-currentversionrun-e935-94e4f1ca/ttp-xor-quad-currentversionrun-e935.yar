rule TTP_XOR_QUAD_CurrentVersionRun_e935 {
  strings:
    $key_e935 = { ba 5a [2] 9e 54 [2] b5 78 [2] 9b 5a [2] 8f 41 [2] 80 5b [2] 9e 46 [2] 9c 47 [2] 87 41 [2] 9b 46 [2] 87 69 }

  condition:
    any of them
}