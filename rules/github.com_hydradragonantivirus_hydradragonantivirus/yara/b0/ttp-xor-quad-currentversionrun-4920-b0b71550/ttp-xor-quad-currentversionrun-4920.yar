rule TTP_XOR_QUAD_CurrentVersionRun_4920 {
  strings:
    $key_4920 = { 1a 4f [2] 3e 41 [2] 15 6d [2] 3b 4f [2] 2f 54 [2] 20 4e [2] 3e 53 [2] 3c 52 [2] 27 54 [2] 3b 53 [2] 27 7c }

  condition:
    any of them
}