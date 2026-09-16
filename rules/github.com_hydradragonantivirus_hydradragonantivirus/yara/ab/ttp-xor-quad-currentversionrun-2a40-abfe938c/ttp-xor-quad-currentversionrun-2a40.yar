rule TTP_XOR_QUAD_CurrentVersionRun_2a40 {
  strings:
    $key_2a40 = { 79 2f [2] 5d 21 [2] 76 0d [2] 58 2f [2] 4c 34 [2] 43 2e [2] 5d 33 [2] 5f 32 [2] 44 34 [2] 58 33 [2] 44 1c }

  condition:
    any of them
}