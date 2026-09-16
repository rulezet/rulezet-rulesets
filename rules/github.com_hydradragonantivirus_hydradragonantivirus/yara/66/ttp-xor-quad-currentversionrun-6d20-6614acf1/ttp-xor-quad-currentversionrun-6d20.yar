rule TTP_XOR_QUAD_CurrentVersionRun_6d20 {
  strings:
    $key_6d20 = { 3e 4f [2] 1a 41 [2] 31 6d [2] 1f 4f [2] 0b 54 [2] 04 4e [2] 1a 53 [2] 18 52 [2] 03 54 [2] 1f 53 [2] 03 7c }

  condition:
    any of them
}