rule TTP_XOR_QUAD_CurrentVersionRun_4040 {
  strings:
    $key_4040 = { 13 2f [2] 37 21 [2] 1c 0d [2] 32 2f [2] 26 34 [2] 29 2e [2] 37 33 [2] 35 32 [2] 2e 34 [2] 32 33 [2] 2e 1c }

  condition:
    any of them
}