rule TTP_XOR_QUAD_CurrentVersionRun_401a {
  strings:
    $key_401a = { 13 75 [2] 37 7b [2] 1c 57 [2] 32 75 [2] 26 6e [2] 29 74 [2] 37 69 [2] 35 68 [2] 2e 6e [2] 32 69 [2] 2e 46 }

  condition:
    any of them
}