rule TTP_XOR_QUAD_CurrentVersionRun_257a {
  strings:
    $key_257a = { 76 15 [2] 52 1b [2] 79 37 [2] 57 15 [2] 43 0e [2] 4c 14 [2] 52 09 [2] 50 08 [2] 4b 0e [2] 57 09 [2] 4b 26 }

  condition:
    any of them
}