rule TTP_XOR_QUAD_CurrentVersionRun_1af8 {
  strings:
    $key_1af8 = { 49 97 [2] 6d 99 [2] 46 b5 [2] 68 97 [2] 7c 8c [2] 73 96 [2] 6d 8b [2] 6f 8a [2] 74 8c [2] 68 8b [2] 74 a4 }

  condition:
    any of them
}