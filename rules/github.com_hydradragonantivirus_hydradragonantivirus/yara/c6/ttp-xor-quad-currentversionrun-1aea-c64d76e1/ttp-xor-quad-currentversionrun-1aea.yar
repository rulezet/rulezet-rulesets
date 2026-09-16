rule TTP_XOR_QUAD_CurrentVersionRun_1aea {
  strings:
    $key_1aea = { 49 85 [2] 6d 8b [2] 46 a7 [2] 68 85 [2] 7c 9e [2] 73 84 [2] 6d 99 [2] 6f 98 [2] 74 9e [2] 68 99 [2] 74 b6 }

  condition:
    any of them
}