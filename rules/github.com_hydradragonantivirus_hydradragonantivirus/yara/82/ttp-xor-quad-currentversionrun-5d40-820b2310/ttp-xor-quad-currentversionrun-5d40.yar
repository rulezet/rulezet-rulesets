rule TTP_XOR_QUAD_CurrentVersionRun_5d40 {
  strings:
    $key_5d40 = { 0e 2f [2] 2a 21 [2] 01 0d [2] 2f 2f [2] 3b 34 [2] 34 2e [2] 2a 33 [2] 28 32 [2] 33 34 [2] 2f 33 [2] 33 1c }

  condition:
    any of them
}