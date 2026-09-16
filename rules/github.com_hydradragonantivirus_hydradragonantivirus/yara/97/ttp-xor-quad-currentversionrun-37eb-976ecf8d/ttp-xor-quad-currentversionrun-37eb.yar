rule TTP_XOR_QUAD_CurrentVersionRun_37eb {
  strings:
    $key_37eb = { 64 84 [2] 40 8a [2] 6b a6 [2] 45 84 [2] 51 9f [2] 5e 85 [2] 40 98 [2] 42 99 [2] 59 9f [2] 45 98 [2] 59 b7 }

  condition:
    any of them
}