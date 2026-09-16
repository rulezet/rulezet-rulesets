rule TTP_XOR_QUAD_CurrentVersionRun_3c1a {
  strings:
    $key_3c1a = { 6f 75 [2] 4b 7b [2] 60 57 [2] 4e 75 [2] 5a 6e [2] 55 74 [2] 4b 69 [2] 49 68 [2] 52 6e [2] 4e 69 [2] 52 46 }

  condition:
    any of them
}