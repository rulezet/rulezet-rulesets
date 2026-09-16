rule TTP_XOR_QUAD_CurrentVersionRun_6840 {
  strings:
    $key_6840 = { 3b 2f [2] 1f 21 [2] 34 0d [2] 1a 2f [2] 0e 34 [2] 01 2e [2] 1f 33 [2] 1d 32 [2] 06 34 [2] 1a 33 [2] 06 1c }

  condition:
    any of them
}