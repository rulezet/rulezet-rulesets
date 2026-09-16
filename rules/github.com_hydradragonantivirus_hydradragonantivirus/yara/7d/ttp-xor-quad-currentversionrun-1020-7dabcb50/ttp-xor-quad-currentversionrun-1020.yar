rule TTP_XOR_QUAD_CurrentVersionRun_1020 {
  strings:
    $key_1020 = { 43 4f [2] 67 41 [2] 4c 6d [2] 62 4f [2] 76 54 [2] 79 4e [2] 67 53 [2] 65 52 [2] 7e 54 [2] 62 53 [2] 7e 7c }

  condition:
    any of them
}