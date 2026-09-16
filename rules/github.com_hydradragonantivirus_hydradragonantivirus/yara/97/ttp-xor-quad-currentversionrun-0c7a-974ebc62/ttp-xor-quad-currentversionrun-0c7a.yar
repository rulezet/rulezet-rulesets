rule TTP_XOR_QUAD_CurrentVersionRun_0c7a {
  strings:
    $key_0c7a = { 5f 15 [2] 7b 1b [2] 50 37 [2] 7e 15 [2] 6a 0e [2] 65 14 [2] 7b 09 [2] 79 08 [2] 62 0e [2] 7e 09 [2] 62 26 }

  condition:
    any of them
}