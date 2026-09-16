rule TTP_XOR_QUAD_CurrentVersionRun_247a {
  strings:
    $key_247a = { 77 15 [2] 53 1b [2] 78 37 [2] 56 15 [2] 42 0e [2] 4d 14 [2] 53 09 [2] 51 08 [2] 4a 0e [2] 56 09 [2] 4a 26 }

  condition:
    any of them
}