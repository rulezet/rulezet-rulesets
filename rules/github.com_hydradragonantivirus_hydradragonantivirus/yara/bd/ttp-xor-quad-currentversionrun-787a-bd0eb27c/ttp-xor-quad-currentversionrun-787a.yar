rule TTP_XOR_QUAD_CurrentVersionRun_787a {
  strings:
    $key_787a = { 2b 15 [2] 0f 1b [2] 24 37 [2] 0a 15 [2] 1e 0e [2] 11 14 [2] 0f 09 [2] 0d 08 [2] 16 0e [2] 0a 09 [2] 16 26 }

  condition:
    any of them
}