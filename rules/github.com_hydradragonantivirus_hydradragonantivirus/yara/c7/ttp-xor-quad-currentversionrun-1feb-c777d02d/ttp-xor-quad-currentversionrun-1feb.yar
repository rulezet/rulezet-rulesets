rule TTP_XOR_QUAD_CurrentVersionRun_1feb {
  strings:
    $key_1feb = { 4c 84 [2] 68 8a [2] 43 a6 [2] 6d 84 [2] 79 9f [2] 76 85 [2] 68 98 [2] 6a 99 [2] 71 9f [2] 6d 98 [2] 71 b7 }

  condition:
    any of them
}