rule TTP_XOR_QUAD_CurrentVersionRun_361a {
  strings:
    $key_361a = { 65 75 [2] 41 7b [2] 6a 57 [2] 44 75 [2] 50 6e [2] 5f 74 [2] 41 69 [2] 43 68 [2] 58 6e [2] 44 69 [2] 58 46 }

  condition:
    any of them
}