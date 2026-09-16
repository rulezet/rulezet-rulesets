rule TTP_XOR_QUAD_CurrentVersionRun_476a {
  strings:
    $key_476a = { 14 05 [2] 30 0b [2] 1b 27 [2] 35 05 [2] 21 1e [2] 2e 04 [2] 30 19 [2] 32 18 [2] 29 1e [2] 35 19 [2] 29 36 }

  condition:
    any of them
}