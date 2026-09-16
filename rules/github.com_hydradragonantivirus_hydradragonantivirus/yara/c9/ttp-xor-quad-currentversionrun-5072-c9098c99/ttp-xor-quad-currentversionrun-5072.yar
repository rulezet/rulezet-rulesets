rule TTP_XOR_QUAD_CurrentVersionRun_5072 {
  strings:
    $key_5072 = { 03 1d [2] 27 13 [2] 0c 3f [2] 22 1d [2] 36 06 [2] 39 1c [2] 27 01 [2] 25 00 [2] 3e 06 [2] 22 01 [2] 3e 2e }

  condition:
    any of them
}