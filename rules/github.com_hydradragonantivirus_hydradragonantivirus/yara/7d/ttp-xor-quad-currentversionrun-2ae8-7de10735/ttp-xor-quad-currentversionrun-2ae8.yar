rule TTP_XOR_QUAD_CurrentVersionRun_2ae8 {
  strings:
    $key_2ae8 = { 79 87 [2] 5d 89 [2] 76 a5 [2] 58 87 [2] 4c 9c [2] 43 86 [2] 5d 9b [2] 5f 9a [2] 44 9c [2] 58 9b [2] 44 b4 }

  condition:
    any of them
}