rule TTP_XOR_QUAD_CurrentVersionRun_5fea {
  strings:
    $key_5fea = { 0c 85 [2] 28 8b [2] 03 a7 [2] 2d 85 [2] 39 9e [2] 36 84 [2] 28 99 [2] 2a 98 [2] 31 9e [2] 2d 99 [2] 31 b6 }

  condition:
    any of them
}