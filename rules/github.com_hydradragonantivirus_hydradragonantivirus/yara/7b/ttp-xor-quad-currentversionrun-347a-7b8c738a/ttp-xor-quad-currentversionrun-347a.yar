rule TTP_XOR_QUAD_CurrentVersionRun_347a {
  strings:
    $key_347a = { 67 15 [2] 43 1b [2] 68 37 [2] 46 15 [2] 52 0e [2] 5d 14 [2] 43 09 [2] 41 08 [2] 5a 0e [2] 46 09 [2] 5a 26 }

  condition:
    any of them
}