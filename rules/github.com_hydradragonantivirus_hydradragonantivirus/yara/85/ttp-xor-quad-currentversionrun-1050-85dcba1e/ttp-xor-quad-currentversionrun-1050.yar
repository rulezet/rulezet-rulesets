rule TTP_XOR_QUAD_CurrentVersionRun_1050 {
  strings:
    $key_1050 = { 43 3f [2] 67 31 [2] 4c 1d [2] 62 3f [2] 76 24 [2] 79 3e [2] 67 23 [2] 65 22 [2] 7e 24 [2] 62 23 [2] 7e 0c }

  condition:
    any of them
}