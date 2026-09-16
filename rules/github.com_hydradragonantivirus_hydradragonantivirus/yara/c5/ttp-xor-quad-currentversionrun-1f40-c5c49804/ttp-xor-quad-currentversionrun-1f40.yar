rule TTP_XOR_QUAD_CurrentVersionRun_1f40 {
  strings:
    $key_1f40 = { 4c 2f [2] 68 21 [2] 43 0d [2] 6d 2f [2] 79 34 [2] 76 2e [2] 68 33 [2] 6a 32 [2] 71 34 [2] 6d 33 [2] 71 1c }

  condition:
    any of them
}