rule TTP_XOR_QUAD_CurrentVersionRun_657a {
  strings:
    $key_657a = { 36 15 [2] 12 1b [2] 39 37 [2] 17 15 [2] 03 0e [2] 0c 14 [2] 12 09 [2] 10 08 [2] 0b 0e [2] 17 09 [2] 0b 26 }

  condition:
    any of them
}