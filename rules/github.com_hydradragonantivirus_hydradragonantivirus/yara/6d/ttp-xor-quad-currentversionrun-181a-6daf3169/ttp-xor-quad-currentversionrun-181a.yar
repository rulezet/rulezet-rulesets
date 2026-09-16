rule TTP_XOR_QUAD_CurrentVersionRun_181a {
  strings:
    $key_181a = { 4b 75 [2] 6f 7b [2] 44 57 [2] 6a 75 [2] 7e 6e [2] 71 74 [2] 6f 69 [2] 6d 68 [2] 76 6e [2] 6a 69 [2] 76 46 }

  condition:
    any of them
}