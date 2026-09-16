rule TTP_XOR_QUAD_CurrentVersionRun_0b1d {
  strings:
    $key_0b1d = { 58 72 [2] 7c 7c [2] 57 50 [2] 79 72 [2] 6d 69 [2] 62 73 [2] 7c 6e [2] 7e 6f [2] 65 69 [2] 79 6e [2] 65 41 }

  condition:
    any of them
}