rule TTP_XOR_QUAD_CurrentVersionRun_221a {
  strings:
    $key_221a = { 71 75 [2] 55 7b [2] 7e 57 [2] 50 75 [2] 44 6e [2] 4b 74 [2] 55 69 [2] 57 68 [2] 4c 6e [2] 50 69 [2] 4c 46 }

  condition:
    any of them
}