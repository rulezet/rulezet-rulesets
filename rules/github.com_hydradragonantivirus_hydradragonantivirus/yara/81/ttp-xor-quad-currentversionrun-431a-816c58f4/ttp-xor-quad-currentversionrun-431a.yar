rule TTP_XOR_QUAD_CurrentVersionRun_431a {
  strings:
    $key_431a = { 10 75 [2] 34 7b [2] 1f 57 [2] 31 75 [2] 25 6e [2] 2a 74 [2] 34 69 [2] 36 68 [2] 2d 6e [2] 31 69 [2] 2d 46 }

  condition:
    any of them
}