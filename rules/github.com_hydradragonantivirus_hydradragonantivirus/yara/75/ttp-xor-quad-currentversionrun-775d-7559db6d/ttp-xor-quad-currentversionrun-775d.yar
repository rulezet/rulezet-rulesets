rule TTP_XOR_QUAD_CurrentVersionRun_775d {
  strings:
    $key_775d = { 24 32 [2] 00 3c [2] 2b 10 [2] 05 32 [2] 11 29 [2] 1e 33 [2] 00 2e [2] 02 2f [2] 19 29 [2] 05 2e [2] 19 01 }

  condition:
    any of them
}