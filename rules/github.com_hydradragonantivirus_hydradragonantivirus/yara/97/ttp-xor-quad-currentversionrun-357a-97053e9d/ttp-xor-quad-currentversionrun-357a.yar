rule TTP_XOR_QUAD_CurrentVersionRun_357a {
  strings:
    $key_357a = { 66 15 [2] 42 1b [2] 69 37 [2] 47 15 [2] 53 0e [2] 5c 14 [2] 42 09 [2] 40 08 [2] 5b 0e [2] 47 09 [2] 5b 26 }

  condition:
    any of them
}