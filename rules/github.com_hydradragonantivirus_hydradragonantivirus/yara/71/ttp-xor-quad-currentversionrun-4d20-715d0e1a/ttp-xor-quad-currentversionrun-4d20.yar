rule TTP_XOR_QUAD_CurrentVersionRun_4d20 {
  strings:
    $key_4d20 = { 1e 4f [2] 3a 41 [2] 11 6d [2] 3f 4f [2] 2b 54 [2] 24 4e [2] 3a 53 [2] 38 52 [2] 23 54 [2] 3f 53 [2] 23 7c }

  condition:
    any of them
}