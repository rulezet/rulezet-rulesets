rule TTP_XOR_QUAD_CurrentVersionRun_041a {
  strings:
    $key_041a = { 57 75 [2] 73 7b [2] 58 57 [2] 76 75 [2] 62 6e [2] 6d 74 [2] 73 69 [2] 71 68 [2] 6a 6e [2] 76 69 [2] 6a 46 }

  condition:
    any of them
}