rule TTP_XOR_QUAD_CurrentVersionRun_5d1a {
  strings:
    $key_5d1a = { 0e 75 [2] 2a 7b [2] 01 57 [2] 2f 75 [2] 3b 6e [2] 34 74 [2] 2a 69 [2] 28 68 [2] 33 6e [2] 2f 69 [2] 33 46 }

  condition:
    any of them
}