rule TTP_XOR_QUAD_CurrentVersionRun_2b1a {
  strings:
    $key_2b1a = { 78 75 [2] 5c 7b [2] 77 57 [2] 59 75 [2] 4d 6e [2] 42 74 [2] 5c 69 [2] 5e 68 [2] 45 6e [2] 59 69 [2] 45 46 }

  condition:
    any of them
}