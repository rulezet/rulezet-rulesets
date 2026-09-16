rule TTP_XOR_QUAD_CurrentVersionRun_735d {
  strings:
    $key_735d = { 20 32 [2] 04 3c [2] 2f 10 [2] 01 32 [2] 15 29 [2] 1a 33 [2] 04 2e [2] 06 2f [2] 1d 29 [2] 01 2e [2] 1d 01 }

  condition:
    any of them
}