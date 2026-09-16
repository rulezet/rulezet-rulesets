rule TTP_XOR_QUAD_CurrentVersionRun_1ff8 {
  strings:
    $key_1ff8 = { 4c 97 [2] 68 99 [2] 43 b5 [2] 6d 97 [2] 79 8c [2] 76 96 [2] 68 8b [2] 6a 8a [2] 71 8c [2] 6d 8b [2] 71 a4 }

  condition:
    any of them
}