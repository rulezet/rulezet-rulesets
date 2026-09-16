rule TTP_XOR_QUAD_CurrentVersionRun_476b {
  strings:
    $key_476b = { 14 04 [2] 30 0a [2] 1b 26 [2] 35 04 [2] 21 1f [2] 2e 05 [2] 30 18 [2] 32 19 [2] 29 1f [2] 35 18 [2] 29 37 }

  condition:
    any of them
}