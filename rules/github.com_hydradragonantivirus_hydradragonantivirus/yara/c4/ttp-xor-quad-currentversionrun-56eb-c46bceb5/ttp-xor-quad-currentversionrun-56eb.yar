rule TTP_XOR_QUAD_CurrentVersionRun_56eb {
  strings:
    $key_56eb = { 05 84 [2] 21 8a [2] 0a a6 [2] 24 84 [2] 30 9f [2] 3f 85 [2] 21 98 [2] 23 99 [2] 38 9f [2] 24 98 [2] 38 b7 }

  condition:
    any of them
}