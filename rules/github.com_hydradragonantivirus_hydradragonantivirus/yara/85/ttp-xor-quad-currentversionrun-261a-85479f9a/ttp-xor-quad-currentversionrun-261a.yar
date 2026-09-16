rule TTP_XOR_QUAD_CurrentVersionRun_261a {
  strings:
    $key_261a = { 75 75 [2] 51 7b [2] 7a 57 [2] 54 75 [2] 40 6e [2] 4f 74 [2] 51 69 [2] 53 68 [2] 48 6e [2] 54 69 [2] 48 46 }

  condition:
    any of them
}