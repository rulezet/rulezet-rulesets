rule TTP_XOR_QUAD_CurrentVersionRun_1a09 {
  strings:
    $key_1a09 = { 49 66 [2] 6d 68 [2] 46 44 [2] 68 66 [2] 7c 7d [2] 73 67 [2] 6d 7a [2] 6f 7b [2] 74 7d [2] 68 7a [2] 74 55 }

  condition:
    any of them
}