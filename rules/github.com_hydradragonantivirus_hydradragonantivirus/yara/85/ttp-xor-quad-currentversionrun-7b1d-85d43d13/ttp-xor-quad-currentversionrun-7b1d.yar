rule TTP_XOR_QUAD_CurrentVersionRun_7b1d {
  strings:
    $key_7b1d = { 28 72 [2] 0c 7c [2] 27 50 [2] 09 72 [2] 1d 69 [2] 12 73 [2] 0c 6e [2] 0e 6f [2] 15 69 [2] 09 6e [2] 15 41 }

  condition:
    any of them
}