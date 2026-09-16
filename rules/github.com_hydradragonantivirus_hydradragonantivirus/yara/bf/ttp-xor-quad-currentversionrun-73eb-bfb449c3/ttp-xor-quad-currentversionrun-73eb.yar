rule TTP_XOR_QUAD_CurrentVersionRun_73eb {
  strings:
    $key_73eb = { 20 84 [2] 04 8a [2] 2f a6 [2] 01 84 [2] 15 9f [2] 1a 85 [2] 04 98 [2] 06 99 [2] 1d 9f [2] 01 98 [2] 1d b7 }

  condition:
    any of them
}