rule TTP_XOR_QUAD_CurrentVersionRun_337a {
  strings:
    $key_337a = { 60 15 [2] 44 1b [2] 6f 37 [2] 41 15 [2] 55 0e [2] 5a 14 [2] 44 09 [2] 46 08 [2] 5d 0e [2] 41 09 [2] 5d 26 }

  condition:
    any of them
}