rule TTP_XOR_QUAD_CurrentVersionRun_4620 {
  strings:
    $key_4620 = { 15 4f [2] 31 41 [2] 1a 6d [2] 34 4f [2] 20 54 [2] 2f 4e [2] 31 53 [2] 33 52 [2] 28 54 [2] 34 53 [2] 28 7c }

  condition:
    any of them
}