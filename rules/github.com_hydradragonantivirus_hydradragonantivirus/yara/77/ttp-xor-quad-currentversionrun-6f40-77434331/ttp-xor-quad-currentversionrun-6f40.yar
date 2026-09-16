rule TTP_XOR_QUAD_CurrentVersionRun_6f40 {
  strings:
    $key_6f40 = { 3c 2f [2] 18 21 [2] 33 0d [2] 1d 2f [2] 09 34 [2] 06 2e [2] 18 33 [2] 1a 32 [2] 01 34 [2] 1d 33 [2] 01 1c }

  condition:
    any of them
}