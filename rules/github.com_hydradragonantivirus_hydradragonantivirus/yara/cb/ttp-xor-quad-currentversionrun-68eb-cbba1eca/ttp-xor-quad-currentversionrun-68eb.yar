rule TTP_XOR_QUAD_CurrentVersionRun_68eb {
  strings:
    $key_68eb = { 3b 84 [2] 1f 8a [2] 34 a6 [2] 1a 84 [2] 0e 9f [2] 01 85 [2] 1f 98 [2] 1d 99 [2] 06 9f [2] 1a 98 [2] 06 b7 }

  condition:
    any of them
}