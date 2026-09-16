rule TTP_XOR_QUAD_CurrentVersionRun_7d7a {
  strings:
    $key_7d7a = { 2e 15 [2] 0a 1b [2] 21 37 [2] 0f 15 [2] 1b 0e [2] 14 14 [2] 0a 09 [2] 08 08 [2] 13 0e [2] 0f 09 [2] 13 26 }

  condition:
    any of them
}