rule TTP_XOR_QUAD_CurrentVersionRun_6d1a {
  strings:
    $key_6d1a = { 3e 75 [2] 1a 7b [2] 31 57 [2] 1f 75 [2] 0b 6e [2] 04 74 [2] 1a 69 [2] 18 68 [2] 03 6e [2] 1f 69 [2] 03 46 }

  condition:
    any of them
}