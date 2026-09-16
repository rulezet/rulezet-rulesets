rule TTP_XOR_QUAD_CurrentVersionRun_6c1a {
  strings:
    $key_6c1a = { 3f 75 [2] 1b 7b [2] 30 57 [2] 1e 75 [2] 0a 6e [2] 05 74 [2] 1b 69 [2] 19 68 [2] 02 6e [2] 1e 69 [2] 02 46 }

  condition:
    any of them
}