rule TTP_XOR_QUAD_CurrentVersionRun_5220 {
  strings:
    $key_5220 = { 01 4f [2] 25 41 [2] 0e 6d [2] 20 4f [2] 34 54 [2] 3b 4e [2] 25 53 [2] 27 52 [2] 3c 54 [2] 20 53 [2] 3c 7c }

  condition:
    any of them
}