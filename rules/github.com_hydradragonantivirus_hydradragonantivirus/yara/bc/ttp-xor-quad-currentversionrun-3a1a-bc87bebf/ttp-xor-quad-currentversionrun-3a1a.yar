rule TTP_XOR_QUAD_CurrentVersionRun_3a1a {
  strings:
    $key_3a1a = { 69 75 [2] 4d 7b [2] 66 57 [2] 48 75 [2] 5c 6e [2] 53 74 [2] 4d 69 [2] 4f 68 [2] 54 6e [2] 48 69 [2] 54 46 }

  condition:
    any of them
}