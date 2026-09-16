rule TTP_XOR_QUAD_CurrentVersionRun_3b7a {
  strings:
    $key_3b7a = { 68 15 [2] 4c 1b [2] 67 37 [2] 49 15 [2] 5d 0e [2] 52 14 [2] 4c 09 [2] 4e 08 [2] 55 0e [2] 49 09 [2] 55 26 }

  condition:
    any of them
}