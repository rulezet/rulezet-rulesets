rule TTP_XOR_QUAD_CurrentVersionRun_2aeb {
  strings:
    $key_2aeb = { 79 84 [2] 5d 8a [2] 76 a6 [2] 58 84 [2] 4c 9f [2] 43 85 [2] 5d 98 [2] 5f 99 [2] 44 9f [2] 58 98 [2] 44 b7 }

  condition:
    any of them
}