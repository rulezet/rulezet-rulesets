rule TTP_XOR_QUAD_CurrentVersionRun_40eb {
  strings:
    $key_40eb = { 13 84 [2] 37 8a [2] 1c a6 [2] 32 84 [2] 26 9f [2] 29 85 [2] 37 98 [2] 35 99 [2] 2e 9f [2] 32 98 [2] 2e b7 }

  condition:
    any of them
}