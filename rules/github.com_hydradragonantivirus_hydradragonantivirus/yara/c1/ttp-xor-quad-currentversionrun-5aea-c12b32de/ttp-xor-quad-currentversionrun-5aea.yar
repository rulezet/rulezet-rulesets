rule TTP_XOR_QUAD_CurrentVersionRun_5aea {
  strings:
    $key_5aea = { 09 85 [2] 2d 8b [2] 06 a7 [2] 28 85 [2] 3c 9e [2] 33 84 [2] 2d 99 [2] 2f 98 [2] 34 9e [2] 28 99 [2] 34 b6 }

  condition:
    any of them
}