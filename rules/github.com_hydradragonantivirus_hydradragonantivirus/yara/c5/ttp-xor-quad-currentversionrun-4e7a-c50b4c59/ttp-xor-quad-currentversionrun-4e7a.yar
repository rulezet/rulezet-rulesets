rule TTP_XOR_QUAD_CurrentVersionRun_4e7a {
  strings:
    $key_4e7a = { 1d 15 [2] 39 1b [2] 12 37 [2] 3c 15 [2] 28 0e [2] 27 14 [2] 39 09 [2] 3b 08 [2] 20 0e [2] 3c 09 [2] 20 26 }

  condition:
    any of them
}