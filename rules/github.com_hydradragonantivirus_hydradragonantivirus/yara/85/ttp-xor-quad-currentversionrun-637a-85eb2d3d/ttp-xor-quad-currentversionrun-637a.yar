rule TTP_XOR_QUAD_CurrentVersionRun_637a {
  strings:
    $key_637a = { 30 15 [2] 14 1b [2] 3f 37 [2] 11 15 [2] 05 0e [2] 0a 14 [2] 14 09 [2] 16 08 [2] 0d 0e [2] 11 09 [2] 0d 26 }

  condition:
    any of them
}