rule TTP_XOR_QUAD_CurrentVersionRun_2520 {
  strings:
    $key_2520 = { 76 4f [2] 52 41 [2] 79 6d [2] 57 4f [2] 43 54 [2] 4c 4e [2] 52 53 [2] 50 52 [2] 4b 54 [2] 57 53 [2] 4b 7c }

  condition:
    any of them
}