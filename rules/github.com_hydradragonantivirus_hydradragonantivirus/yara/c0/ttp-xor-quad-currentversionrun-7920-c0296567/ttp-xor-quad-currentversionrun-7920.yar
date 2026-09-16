rule TTP_XOR_QUAD_CurrentVersionRun_7920 {
  strings:
    $key_7920 = { 2a 4f [2] 0e 41 [2] 25 6d [2] 0b 4f [2] 1f 54 [2] 10 4e [2] 0e 53 [2] 0c 52 [2] 17 54 [2] 0b 53 [2] 17 7c }

  condition:
    any of them
}