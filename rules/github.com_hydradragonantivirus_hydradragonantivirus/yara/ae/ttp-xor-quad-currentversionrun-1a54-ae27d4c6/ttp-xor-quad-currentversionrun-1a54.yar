rule TTP_XOR_QUAD_CurrentVersionRun_1a54 {
  strings:
    $key_1a54 = { 49 3b [2] 6d 35 [2] 46 19 [2] 68 3b [2] 7c 20 [2] 73 3a [2] 6d 27 [2] 6f 26 [2] 74 20 [2] 68 27 [2] 74 08 }

  condition:
    any of them
}