rule TTP_XOR_QUAD_CurrentVersionRun_7eeb {
  strings:
    $key_7eeb = { 2d 84 [2] 09 8a [2] 22 a6 [2] 0c 84 [2] 18 9f [2] 17 85 [2] 09 98 [2] 0b 99 [2] 10 9f [2] 0c 98 [2] 10 b7 }

  condition:
    any of them
}