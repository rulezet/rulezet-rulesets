rule TTP_XOR_QUAD_CurrentVersionRun_0eeb {
  strings:
    $key_0eeb = { 5d 84 [2] 79 8a [2] 52 a6 [2] 7c 84 [2] 68 9f [2] 67 85 [2] 79 98 [2] 7b 99 [2] 60 9f [2] 7c 98 [2] 60 b7 }

  condition:
    any of them
}