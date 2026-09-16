rule TTP_XOR_QUAD_CurrentVersionRun_6fea {
  strings:
    $key_6fea = { 3c 85 [2] 18 8b [2] 33 a7 [2] 1d 85 [2] 09 9e [2] 06 84 [2] 18 99 [2] 1a 98 [2] 01 9e [2] 1d 99 [2] 01 b6 }

  condition:
    any of them
}