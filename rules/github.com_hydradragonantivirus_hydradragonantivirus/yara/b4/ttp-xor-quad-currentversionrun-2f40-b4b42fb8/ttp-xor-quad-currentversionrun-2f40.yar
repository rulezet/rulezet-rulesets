rule TTP_XOR_QUAD_CurrentVersionRun_2f40 {
  strings:
    $key_2f40 = { 7c 2f [2] 58 21 [2] 73 0d [2] 5d 2f [2] 49 34 [2] 46 2e [2] 58 33 [2] 5a 32 [2] 41 34 [2] 5d 33 [2] 41 1c }

  condition:
    any of them
}