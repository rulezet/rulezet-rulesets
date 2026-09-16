rule TTP_XOR_QUAD_CurrentVersionRun_0e1d {
  strings:
    $key_0e1d = { 5d 72 [2] 79 7c [2] 52 50 [2] 7c 72 [2] 68 69 [2] 67 73 [2] 79 6e [2] 7b 6f [2] 60 69 [2] 7c 6e [2] 60 41 }

  condition:
    any of them
}