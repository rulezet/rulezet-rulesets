rule TTP_XOR_QUAD_CurrentVersionRun_5aeb {
  strings:
    $key_5aeb = { 09 84 [2] 2d 8a [2] 06 a6 [2] 28 84 [2] 3c 9f [2] 33 85 [2] 2d 98 [2] 2f 99 [2] 34 9f [2] 28 98 [2] 34 b7 }

  condition:
    any of them
}