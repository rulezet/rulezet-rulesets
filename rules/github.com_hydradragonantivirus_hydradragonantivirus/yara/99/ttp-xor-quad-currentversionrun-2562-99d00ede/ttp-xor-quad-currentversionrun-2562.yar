rule TTP_XOR_QUAD_CurrentVersionRun_2562 {
  strings:
    $key_2562 = { 76 0d [2] 52 03 [2] 79 2f [2] 57 0d [2] 43 16 [2] 4c 0c [2] 52 11 [2] 50 10 [2] 4b 16 [2] 57 11 [2] 4b 3e }

  condition:
    any of them
}