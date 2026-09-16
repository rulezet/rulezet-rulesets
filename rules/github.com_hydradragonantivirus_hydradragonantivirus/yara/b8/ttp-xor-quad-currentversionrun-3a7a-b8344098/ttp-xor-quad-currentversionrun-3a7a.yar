rule TTP_XOR_QUAD_CurrentVersionRun_3a7a {
  strings:
    $key_3a7a = { 69 15 [2] 4d 1b [2] 66 37 [2] 48 15 [2] 5c 0e [2] 53 14 [2] 4d 09 [2] 4f 08 [2] 54 0e [2] 48 09 [2] 54 26 }

  condition:
    any of them
}