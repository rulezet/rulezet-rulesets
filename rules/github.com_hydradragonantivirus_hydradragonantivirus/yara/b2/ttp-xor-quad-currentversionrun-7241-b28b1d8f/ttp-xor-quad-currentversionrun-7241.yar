rule TTP_XOR_QUAD_CurrentVersionRun_7241 {
  strings:
    $key_7241 = { 21 2e [2] 05 20 [2] 2e 0c [2] 00 2e [2] 14 35 [2] 1b 2f [2] 05 32 [2] 07 33 [2] 1c 35 [2] 00 32 [2] 1c 1d }

  condition:
    any of them
}