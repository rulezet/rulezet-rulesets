rule TTP_XOR_QUAD_CurrentVersionRun_1a38 {
  strings:
    $key_1a38 = { 49 57 [2] 6d 59 [2] 46 75 [2] 68 57 [2] 7c 4c [2] 73 56 [2] 6d 4b [2] 6f 4a [2] 74 4c [2] 68 4b [2] 74 64 }

  condition:
    any of them
}