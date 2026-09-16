rule TTP_XOR_QUAD_CurrentVersionRun_0e1a {
  strings:
    $key_0e1a = { 5d 75 [2] 79 7b [2] 52 57 [2] 7c 75 [2] 68 6e [2] 67 74 [2] 79 69 [2] 7b 68 [2] 60 6e [2] 7c 69 [2] 60 46 }

  condition:
    any of them
}