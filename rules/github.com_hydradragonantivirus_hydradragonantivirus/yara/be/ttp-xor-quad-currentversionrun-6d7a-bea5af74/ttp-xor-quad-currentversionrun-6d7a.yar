rule TTP_XOR_QUAD_CurrentVersionRun_6d7a {
  strings:
    $key_6d7a = { 3e 15 [2] 1a 1b [2] 31 37 [2] 1f 15 [2] 0b 0e [2] 04 14 [2] 1a 09 [2] 18 08 [2] 03 0e [2] 1f 09 [2] 03 26 }

  condition:
    any of them
}