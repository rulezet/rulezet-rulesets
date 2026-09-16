rule TTP_XOR_QUAD_CurrentVersionRun_30eb {
  strings:
    $key_30eb = { 63 84 [2] 47 8a [2] 6c a6 [2] 42 84 [2] 56 9f [2] 59 85 [2] 47 98 [2] 45 99 [2] 5e 9f [2] 42 98 [2] 5e b7 }

  condition:
    any of them
}