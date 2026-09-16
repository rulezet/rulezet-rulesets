rule TTP_XOR_QUAD_CurrentVersionRun_7a1a {
  strings:
    $key_7a1a = { 29 75 [2] 0d 7b [2] 26 57 [2] 08 75 [2] 1c 6e [2] 13 74 [2] 0d 69 [2] 0f 68 [2] 14 6e [2] 08 69 [2] 14 46 }

  condition:
    any of them
}