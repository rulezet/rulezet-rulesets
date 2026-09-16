rule TTP_XOR_QUAD_CurrentVersionRun_1550 {
  strings:
    $key_1550 = { 46 3f [2] 62 31 [2] 49 1d [2] 67 3f [2] 73 24 [2] 7c 3e [2] 62 23 [2] 60 22 [2] 7b 24 [2] 67 23 [2] 7b 0c }

  condition:
    any of them
}