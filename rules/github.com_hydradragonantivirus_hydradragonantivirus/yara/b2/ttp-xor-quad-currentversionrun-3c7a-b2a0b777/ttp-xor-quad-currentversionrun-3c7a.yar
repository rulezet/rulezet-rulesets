rule TTP_XOR_QUAD_CurrentVersionRun_3c7a {
  strings:
    $key_3c7a = { 6f 15 [2] 4b 1b [2] 60 37 [2] 4e 15 [2] 5a 0e [2] 55 14 [2] 4b 09 [2] 49 08 [2] 52 0e [2] 4e 09 [2] 52 26 }

  condition:
    any of them
}