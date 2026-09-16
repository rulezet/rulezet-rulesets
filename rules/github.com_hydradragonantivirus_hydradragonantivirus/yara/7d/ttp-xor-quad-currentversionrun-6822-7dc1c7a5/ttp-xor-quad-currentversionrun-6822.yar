rule TTP_XOR_QUAD_CurrentVersionRun_6822 {
  strings:
    $key_6822 = { 3b 4d [2] 1f 43 [2] 34 6f [2] 1a 4d [2] 0e 56 [2] 01 4c [2] 1f 51 [2] 1d 50 [2] 06 56 [2] 1a 51 [2] 06 7e }

  condition:
    any of them
}