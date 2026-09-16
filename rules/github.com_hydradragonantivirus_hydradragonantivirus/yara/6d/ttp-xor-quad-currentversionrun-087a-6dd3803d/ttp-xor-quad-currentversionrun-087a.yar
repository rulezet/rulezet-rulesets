rule TTP_XOR_QUAD_CurrentVersionRun_087a {
  strings:
    $key_087a = { 5b 15 [2] 7f 1b [2] 54 37 [2] 7a 15 [2] 6e 0e [2] 61 14 [2] 7f 09 [2] 7d 08 [2] 66 0e [2] 7a 09 [2] 66 26 }

  condition:
    any of them
}