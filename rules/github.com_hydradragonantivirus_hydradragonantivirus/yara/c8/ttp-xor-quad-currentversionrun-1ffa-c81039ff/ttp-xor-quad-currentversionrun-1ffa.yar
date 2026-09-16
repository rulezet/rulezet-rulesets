rule TTP_XOR_QUAD_CurrentVersionRun_1ffa {
  strings:
    $key_1ffa = { 4c 95 [2] 68 9b [2] 43 b7 [2] 6d 95 [2] 79 8e [2] 76 94 [2] 68 89 [2] 6a 88 [2] 71 8e [2] 6d 89 [2] 71 a6 }

  condition:
    any of them
}