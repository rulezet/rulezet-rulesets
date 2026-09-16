rule TTP_XOR_QUAD_CurrentVersionRun_2af9 {
  strings:
    $key_2af9 = { 79 96 [2] 5d 98 [2] 76 b4 [2] 58 96 [2] 4c 8d [2] 43 97 [2] 5d 8a [2] 5f 8b [2] 44 8d [2] 58 8a [2] 44 a5 }

  condition:
    any of them
}