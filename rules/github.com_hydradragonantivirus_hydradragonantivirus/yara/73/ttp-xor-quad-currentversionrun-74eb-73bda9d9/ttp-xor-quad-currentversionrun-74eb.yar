rule TTP_XOR_QUAD_CurrentVersionRun_74eb {
  strings:
    $key_74eb = { 27 84 [2] 03 8a [2] 28 a6 [2] 06 84 [2] 12 9f [2] 1d 85 [2] 03 98 [2] 01 99 [2] 1a 9f [2] 06 98 [2] 1a b7 }

  condition:
    any of them
}