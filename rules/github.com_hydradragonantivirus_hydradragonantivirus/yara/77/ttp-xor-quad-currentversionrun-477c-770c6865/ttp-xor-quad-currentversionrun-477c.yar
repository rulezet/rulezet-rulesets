rule TTP_XOR_QUAD_CurrentVersionRun_477c {
  strings:
    $key_477c = { 14 13 [2] 30 1d [2] 1b 31 [2] 35 13 [2] 21 08 [2] 2e 12 [2] 30 0f [2] 32 0e [2] 29 08 [2] 35 0f [2] 29 20 }

  condition:
    any of them
}