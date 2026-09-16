rule TTP_XOR_QUAD_CurrentVersionRun_421a {
  strings:
    $key_421a = { 11 75 [2] 35 7b [2] 1e 57 [2] 30 75 [2] 24 6e [2] 2b 74 [2] 35 69 [2] 37 68 [2] 2c 6e [2] 30 69 [2] 2c 46 }

  condition:
    any of them
}