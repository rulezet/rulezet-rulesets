rule TTP_XOR_QUAD_CurrentVersionRun_7e1a {
  strings:
    $key_7e1a = { 2d 75 [2] 09 7b [2] 22 57 [2] 0c 75 [2] 18 6e [2] 17 74 [2] 09 69 [2] 0b 68 [2] 10 6e [2] 0c 69 [2] 10 46 }

  condition:
    any of them
}