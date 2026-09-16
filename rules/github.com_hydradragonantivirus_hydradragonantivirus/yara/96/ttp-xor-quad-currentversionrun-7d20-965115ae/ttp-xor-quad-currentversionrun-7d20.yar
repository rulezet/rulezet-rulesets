rule TTP_XOR_QUAD_CurrentVersionRun_7d20 {
  strings:
    $key_7d20 = { 2e 4f [2] 0a 41 [2] 21 6d [2] 0f 4f [2] 1b 54 [2] 14 4e [2] 0a 53 [2] 08 52 [2] 13 54 [2] 0f 53 [2] 13 7c }

  condition:
    any of them
}