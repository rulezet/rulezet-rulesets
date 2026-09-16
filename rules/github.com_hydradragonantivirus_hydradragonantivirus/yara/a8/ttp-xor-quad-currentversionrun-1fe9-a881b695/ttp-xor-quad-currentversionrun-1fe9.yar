rule TTP_XOR_QUAD_CurrentVersionRun_1fe9 {
  strings:
    $key_1fe9 = { 4c 86 [2] 68 88 [2] 43 a4 [2] 6d 86 [2] 79 9d [2] 76 87 [2] 68 9a [2] 6a 9b [2] 71 9d [2] 6d 9a [2] 71 b5 }

  condition:
    any of them
}