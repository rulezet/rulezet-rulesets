rule TTP_XOR_QUAD_CurrentVersionRun_3e1a {
  strings:
    $key_3e1a = { 6d 75 [2] 49 7b [2] 62 57 [2] 4c 75 [2] 58 6e [2] 57 74 [2] 49 69 [2] 4b 68 [2] 50 6e [2] 4c 69 [2] 50 46 }

  condition:
    any of them
}