rule TTP_XOR_QUAD_CurrentVersionRun_1b1a {
  strings:
    $key_1b1a = { 48 75 [2] 6c 7b [2] 47 57 [2] 69 75 [2] 7d 6e [2] 72 74 [2] 6c 69 [2] 6e 68 [2] 75 6e [2] 69 69 [2] 75 46 }

  condition:
    any of them
}