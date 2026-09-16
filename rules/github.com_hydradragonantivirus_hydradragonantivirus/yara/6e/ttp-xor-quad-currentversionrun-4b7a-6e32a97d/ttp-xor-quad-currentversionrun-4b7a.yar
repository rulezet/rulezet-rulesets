rule TTP_XOR_QUAD_CurrentVersionRun_4b7a {
  strings:
    $key_4b7a = { 18 15 [2] 3c 1b [2] 17 37 [2] 39 15 [2] 2d 0e [2] 22 14 [2] 3c 09 [2] 3e 08 [2] 25 0e [2] 39 09 [2] 25 26 }

  condition:
    any of them
}