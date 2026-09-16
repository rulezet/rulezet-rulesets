rule TTP_XOR_QUAD_CurrentVersionRun_7aeb {
  strings:
    $key_7aeb = { 29 84 [2] 0d 8a [2] 26 a6 [2] 08 84 [2] 1c 9f [2] 13 85 [2] 0d 98 [2] 0f 99 [2] 14 9f [2] 08 98 [2] 14 b7 }

  condition:
    any of them
}