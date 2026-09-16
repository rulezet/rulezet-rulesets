rule TTP_XOR_QUAD_CurrentVersionRun_57eb {
  strings:
    $key_57eb = { 04 84 [2] 20 8a [2] 0b a6 [2] 25 84 [2] 31 9f [2] 3e 85 [2] 20 98 [2] 22 99 [2] 39 9f [2] 25 98 [2] 39 b7 }

  condition:
    any of them
}