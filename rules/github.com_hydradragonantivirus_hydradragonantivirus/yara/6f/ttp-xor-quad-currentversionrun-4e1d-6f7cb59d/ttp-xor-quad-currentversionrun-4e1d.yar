rule TTP_XOR_QUAD_CurrentVersionRun_4e1d {
  strings:
    $key_4e1d = { 1d 72 [2] 39 7c [2] 12 50 [2] 3c 72 [2] 28 69 [2] 27 73 [2] 39 6e [2] 3b 6f [2] 20 69 [2] 3c 6e [2] 20 41 }

  condition:
    any of them
}