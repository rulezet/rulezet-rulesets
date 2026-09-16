rule TTP_XOR_QUAD_CurrentVersionRun_2e7a {
  strings:
    $key_2e7a = { 7d 15 [2] 59 1b [2] 72 37 [2] 5c 15 [2] 48 0e [2] 47 14 [2] 59 09 [2] 5b 08 [2] 40 0e [2] 5c 09 [2] 40 26 }

  condition:
    any of them
}