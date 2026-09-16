rule TTP_XOR_QUAD_CurrentVersionRun_001a {
  strings:
    $key_001a = { 53 75 [2] 77 7b [2] 5c 57 [2] 72 75 [2] 66 6e [2] 69 74 [2] 77 69 [2] 75 68 [2] 6e 6e [2] 72 69 [2] 6e 46 }

  condition:
    any of them
}