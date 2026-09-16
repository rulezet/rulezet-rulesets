rule TTP_XOR_QUAD_CurrentVersionRun_1ae8 {
  strings:
    $key_1ae8 = { 49 87 [2] 6d 89 [2] 46 a5 [2] 68 87 [2] 7c 9c [2] 73 86 [2] 6d 9b [2] 6f 9a [2] 74 9c [2] 68 9b [2] 74 b4 }

  condition:
    any of them
}