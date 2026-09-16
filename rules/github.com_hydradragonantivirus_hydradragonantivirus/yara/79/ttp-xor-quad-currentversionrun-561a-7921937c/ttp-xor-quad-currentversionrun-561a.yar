rule TTP_XOR_QUAD_CurrentVersionRun_561a {
  strings:
    $key_561a = { 05 75 [2] 21 7b [2] 0a 57 [2] 24 75 [2] 30 6e [2] 3f 74 [2] 21 69 [2] 23 68 [2] 38 6e [2] 24 69 [2] 38 46 }

  condition:
    any of them
}