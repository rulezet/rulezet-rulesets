rule TTP_XOR_QUAD_CurrentVersionRun_7c6a {
  strings:
    $key_7c6a = { 2f 05 [2] 0b 0b [2] 20 27 [2] 0e 05 [2] 1a 1e [2] 15 04 [2] 0b 19 [2] 09 18 [2] 12 1e [2] 0e 19 [2] 12 36 }

  condition:
    any of them
}