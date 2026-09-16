rule TTP_XOR_QUAD_CurrentVersionRun_724b {
  strings:
    $key_724b = { 21 24 [2] 05 2a [2] 2e 06 [2] 00 24 [2] 14 3f [2] 1b 25 [2] 05 38 [2] 07 39 [2] 1c 3f [2] 00 38 [2] 1c 17 }

  condition:
    any of them
}