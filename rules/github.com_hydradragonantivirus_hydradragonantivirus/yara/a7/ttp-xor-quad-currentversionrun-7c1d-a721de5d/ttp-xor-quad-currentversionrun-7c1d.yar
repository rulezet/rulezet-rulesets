rule TTP_XOR_QUAD_CurrentVersionRun_7c1d {
  strings:
    $key_7c1d = { 2f 72 [2] 0b 7c [2] 20 50 [2] 0e 72 [2] 1a 69 [2] 15 73 [2] 0b 6e [2] 09 6f [2] 12 69 [2] 0e 6e [2] 12 41 }

  condition:
    any of them
}