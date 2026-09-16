rule TTP_XOR_QUAD_CurrentVersionRun_3e1d {
  strings:
    $key_3e1d = { 6d 72 [2] 49 7c [2] 62 50 [2] 4c 72 [2] 58 69 [2] 57 73 [2] 49 6e [2] 4b 6f [2] 50 69 [2] 4c 6e [2] 50 41 }

  condition:
    any of them
}