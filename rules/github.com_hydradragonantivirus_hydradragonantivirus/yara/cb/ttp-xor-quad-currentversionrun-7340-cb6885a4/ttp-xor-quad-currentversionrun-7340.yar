rule TTP_XOR_QUAD_CurrentVersionRun_7340 {
  strings:
    $key_7340 = { 20 2f [2] 04 21 [2] 2f 0d [2] 01 2f [2] 15 34 [2] 1a 2e [2] 04 33 [2] 06 32 [2] 1d 34 [2] 01 33 [2] 1d 1c }

  condition:
    any of them
}