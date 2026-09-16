rule TTP_XOR_QUAD_CurrentVersionRun_2aea {
  strings:
    $key_2aea = { 79 85 [2] 5d 8b [2] 76 a7 [2] 58 85 [2] 4c 9e [2] 43 84 [2] 5d 99 [2] 5f 98 [2] 44 9e [2] 58 99 [2] 44 b6 }

  condition:
    any of them
}