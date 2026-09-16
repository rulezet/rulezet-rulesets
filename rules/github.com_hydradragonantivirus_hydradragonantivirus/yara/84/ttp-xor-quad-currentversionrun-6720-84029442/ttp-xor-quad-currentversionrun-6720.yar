rule TTP_XOR_QUAD_CurrentVersionRun_6720 {
  strings:
    $key_6720 = { 34 4f [2] 10 41 [2] 3b 6d [2] 15 4f [2] 01 54 [2] 0e 4e [2] 10 53 [2] 12 52 [2] 09 54 [2] 15 53 [2] 09 7c }

  condition:
    any of them
}