rule TTP_XOR_QUAD_CurrentVersionRun_606a {
  strings:
    $key_606a = { 33 05 [2] 17 0b [2] 3c 27 [2] 12 05 [2] 06 1e [2] 09 04 [2] 17 19 [2] 15 18 [2] 0e 1e [2] 12 19 [2] 0e 36 }

  condition:
    any of them
}