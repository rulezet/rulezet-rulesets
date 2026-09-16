rule TTP_XOR_QUAD_CurrentVersionRun_587a {
  strings:
    $key_587a = { 0b 15 [2] 2f 1b [2] 04 37 [2] 2a 15 [2] 3e 0e [2] 31 14 [2] 2f 09 [2] 2d 08 [2] 36 0e [2] 2a 09 [2] 36 26 }

  condition:
    any of them
}