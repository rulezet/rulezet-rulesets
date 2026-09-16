rule TTP_XOR_QUAD_CurrentVersionRun_5d20 {
  strings:
    $key_5d20 = { 0e 4f [2] 2a 41 [2] 01 6d [2] 2f 4f [2] 3b 54 [2] 34 4e [2] 2a 53 [2] 28 52 [2] 33 54 [2] 2f 53 [2] 33 7c }

  condition:
    any of them
}