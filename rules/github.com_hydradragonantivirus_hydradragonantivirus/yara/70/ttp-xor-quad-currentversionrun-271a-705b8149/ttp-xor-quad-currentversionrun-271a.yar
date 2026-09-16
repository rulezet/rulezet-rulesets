rule TTP_XOR_QUAD_CurrentVersionRun_271a {
  strings:
    $key_271a = { 74 75 [2] 50 7b [2] 7b 57 [2] 55 75 [2] 41 6e [2] 4e 74 [2] 50 69 [2] 52 68 [2] 49 6e [2] 55 69 [2] 49 46 }

  condition:
    any of them
}