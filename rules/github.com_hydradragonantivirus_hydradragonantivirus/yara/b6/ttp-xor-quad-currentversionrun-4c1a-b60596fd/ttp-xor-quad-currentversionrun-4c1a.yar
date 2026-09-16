rule TTP_XOR_QUAD_CurrentVersionRun_4c1a {
  strings:
    $key_4c1a = { 1f 75 [2] 3b 7b [2] 10 57 [2] 3e 75 [2] 2a 6e [2] 25 74 [2] 3b 69 [2] 39 68 [2] 22 6e [2] 3e 69 [2] 22 46 }

  condition:
    any of them
}