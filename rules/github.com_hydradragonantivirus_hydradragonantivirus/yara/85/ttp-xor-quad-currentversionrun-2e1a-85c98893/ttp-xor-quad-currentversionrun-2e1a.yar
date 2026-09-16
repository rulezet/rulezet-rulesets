rule TTP_XOR_QUAD_CurrentVersionRun_2e1a {
  strings:
    $key_2e1a = { 7d 75 [2] 59 7b [2] 72 57 [2] 5c 75 [2] 48 6e [2] 47 74 [2] 59 69 [2] 5b 68 [2] 40 6e [2] 5c 69 [2] 40 46 }

  condition:
    any of them
}