rule TTP_XOR_QUAD_CurrentVersionRun_7f1a {
  strings:
    $key_7f1a = { 2c 75 [2] 08 7b [2] 23 57 [2] 0d 75 [2] 19 6e [2] 16 74 [2] 08 69 [2] 0a 68 [2] 11 6e [2] 0d 69 [2] 11 46 }

  condition:
    any of them
}