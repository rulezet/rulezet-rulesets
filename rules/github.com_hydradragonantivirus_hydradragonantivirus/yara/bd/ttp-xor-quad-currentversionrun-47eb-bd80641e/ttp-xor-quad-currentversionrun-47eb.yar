rule TTP_XOR_QUAD_CurrentVersionRun_47eb {
  strings:
    $key_47eb = { 14 84 [2] 30 8a [2] 1b a6 [2] 35 84 [2] 21 9f [2] 2e 85 [2] 30 98 [2] 32 99 [2] 29 9f [2] 35 98 [2] 29 b7 }

  condition:
    any of them
}