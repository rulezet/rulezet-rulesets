rule TTP_XOR_QUAD_CurrentVersionRun_1f7a {
  strings:
    $key_1f7a = { 4c 15 [2] 68 1b [2] 43 37 [2] 6d 15 [2] 79 0e [2] 76 14 [2] 68 09 [2] 6a 08 [2] 71 0e [2] 6d 09 [2] 71 26 }

  condition:
    any of them
}