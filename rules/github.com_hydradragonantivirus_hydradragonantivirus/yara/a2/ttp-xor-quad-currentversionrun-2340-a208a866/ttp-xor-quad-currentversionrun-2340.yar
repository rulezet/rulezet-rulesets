rule TTP_XOR_QUAD_CurrentVersionRun_2340 {
  strings:
    $key_2340 = { 70 2f [2] 54 21 [2] 7f 0d [2] 51 2f [2] 45 34 [2] 4a 2e [2] 54 33 [2] 56 32 [2] 4d 34 [2] 51 33 [2] 4d 1c }

  condition:
    any of them
}