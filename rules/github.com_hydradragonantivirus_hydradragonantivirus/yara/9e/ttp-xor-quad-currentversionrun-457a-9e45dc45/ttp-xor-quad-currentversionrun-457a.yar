rule TTP_XOR_QUAD_CurrentVersionRun_457a {
  strings:
    $key_457a = { 16 15 [2] 32 1b [2] 19 37 [2] 37 15 [2] 23 0e [2] 2c 14 [2] 32 09 [2] 30 08 [2] 2b 0e [2] 37 09 [2] 2b 26 }

  condition:
    any of them
}