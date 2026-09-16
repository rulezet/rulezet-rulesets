rule TTP_XOR_QUAD_CurrentVersionRun_4feb {
  strings:
    $key_4feb = { 1c 84 [2] 38 8a [2] 13 a6 [2] 3d 84 [2] 29 9f [2] 26 85 [2] 38 98 [2] 3a 99 [2] 21 9f [2] 3d 98 [2] 21 b7 }

  condition:
    any of them
}