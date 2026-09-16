rule TTP_XOR_QUAD_CurrentVersionRun_277a {
  strings:
    $key_277a = { 74 15 [2] 50 1b [2] 7b 37 [2] 55 15 [2] 41 0e [2] 4e 14 [2] 50 09 [2] 52 08 [2] 49 0e [2] 55 09 [2] 49 26 }

  condition:
    any of them
}