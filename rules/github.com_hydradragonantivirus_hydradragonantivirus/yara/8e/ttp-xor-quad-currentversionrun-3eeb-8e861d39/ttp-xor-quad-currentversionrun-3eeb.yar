rule TTP_XOR_QUAD_CurrentVersionRun_3eeb {
  strings:
    $key_3eeb = { 6d 84 [2] 49 8a [2] 62 a6 [2] 4c 84 [2] 58 9f [2] 57 85 [2] 49 98 [2] 4b 99 [2] 50 9f [2] 4c 98 [2] 50 b7 }

  condition:
    any of them
}