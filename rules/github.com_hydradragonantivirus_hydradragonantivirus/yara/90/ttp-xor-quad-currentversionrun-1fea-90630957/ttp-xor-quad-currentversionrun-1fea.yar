rule TTP_XOR_QUAD_CurrentVersionRun_1fea {
  strings:
    $key_1fea = { 4c 85 [2] 68 8b [2] 43 a7 [2] 6d 85 [2] 79 9e [2] 76 84 [2] 68 99 [2] 6a 98 [2] 71 9e [2] 6d 99 [2] 71 b6 }

  condition:
    any of them
}