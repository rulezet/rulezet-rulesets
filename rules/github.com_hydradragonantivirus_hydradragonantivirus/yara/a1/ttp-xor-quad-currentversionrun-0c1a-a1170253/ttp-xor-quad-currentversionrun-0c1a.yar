rule TTP_XOR_QUAD_CurrentVersionRun_0c1a {
  strings:
    $key_0c1a = { 5f 75 [2] 7b 7b [2] 50 57 [2] 7e 75 [2] 6a 6e [2] 65 74 [2] 7b 69 [2] 79 68 [2] 62 6e [2] 7e 69 [2] 62 46 }

  condition:
    any of them
}