rule TTP_XOR_QUAD_CurrentVersionRun_1fed {
  strings:
    $key_1fed = { 4c 82 [2] 68 8c [2] 43 a0 [2] 6d 82 [2] 79 99 [2] 76 83 [2] 68 9e [2] 6a 9f [2] 71 99 [2] 6d 9e [2] 71 b1 }

  condition:
    any of them
}