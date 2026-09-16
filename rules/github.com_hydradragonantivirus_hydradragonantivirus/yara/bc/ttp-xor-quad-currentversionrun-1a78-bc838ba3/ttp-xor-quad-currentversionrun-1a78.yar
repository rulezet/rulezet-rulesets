rule TTP_XOR_QUAD_CurrentVersionRun_1a78 {
  strings:
    $key_1a78 = { 49 17 [2] 6d 19 [2] 46 35 [2] 68 17 [2] 7c 0c [2] 73 16 [2] 6d 0b [2] 6f 0a [2] 74 0c [2] 68 0b [2] 74 24 }

  condition:
    any of them
}