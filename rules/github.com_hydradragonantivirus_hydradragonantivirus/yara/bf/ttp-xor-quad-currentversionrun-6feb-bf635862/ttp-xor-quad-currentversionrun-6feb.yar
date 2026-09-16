rule TTP_XOR_QUAD_CurrentVersionRun_6feb {
  strings:
    $key_6feb = { 3c 84 [2] 18 8a [2] 33 a6 [2] 1d 84 [2] 09 9f [2] 06 85 [2] 18 98 [2] 1a 99 [2] 01 9f [2] 1d 98 [2] 01 b7 }

  condition:
    any of them
}