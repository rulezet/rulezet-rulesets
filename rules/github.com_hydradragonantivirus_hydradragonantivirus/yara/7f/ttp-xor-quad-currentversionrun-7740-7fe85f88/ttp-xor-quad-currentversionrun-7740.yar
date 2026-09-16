rule TTP_XOR_QUAD_CurrentVersionRun_7740 {
  strings:
    $key_7740 = { 24 2f [2] 00 21 [2] 2b 0d [2] 05 2f [2] 11 34 [2] 1e 2e [2] 00 33 [2] 02 32 [2] 19 34 [2] 05 33 [2] 19 1c }

  condition:
    any of them
}