rule TTP_XOR_QUAD_CurrentVersionRun_551d {
  strings:
    $key_551d = { 06 72 [2] 22 7c [2] 09 50 [2] 27 72 [2] 33 69 [2] 3c 73 [2] 22 6e [2] 20 6f [2] 3b 69 [2] 27 6e [2] 3b 41 }

  condition:
    any of them
}