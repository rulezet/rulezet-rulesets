rule TTP_XOR_QUAD_CurrentVersionRun_472b {
  strings:
    $key_472b = { 14 44 [2] 30 4a [2] 1b 66 [2] 35 44 [2] 21 5f [2] 2e 45 [2] 30 58 [2] 32 59 [2] 29 5f [2] 35 58 [2] 29 77 }

  condition:
    any of them
}