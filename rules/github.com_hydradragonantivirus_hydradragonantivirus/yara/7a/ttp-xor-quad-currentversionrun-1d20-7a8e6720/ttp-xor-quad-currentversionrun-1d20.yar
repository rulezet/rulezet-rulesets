rule TTP_XOR_QUAD_CurrentVersionRun_1d20 {
  strings:
    $key_1d20 = { 4e 4f [2] 6a 41 [2] 41 6d [2] 6f 4f [2] 7b 54 [2] 74 4e [2] 6a 53 [2] 68 52 [2] 73 54 [2] 6f 53 [2] 73 7c }

  condition:
    any of them
}