rule TTP_XOR_QUAD_CurrentVersionRun_796a {
  strings:
    $key_796a = { 2a 05 [2] 0e 0b [2] 25 27 [2] 0b 05 [2] 1f 1e [2] 10 04 [2] 0e 19 [2] 0c 18 [2] 17 1e [2] 0b 19 [2] 17 36 }

  condition:
    any of them
}