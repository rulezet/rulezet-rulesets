rule TTP_XOR_QUAD_CurrentVersionRun_676a {
  strings:
    $key_676a = { 34 05 [2] 10 0b [2] 3b 27 [2] 15 05 [2] 01 1e [2] 0e 04 [2] 10 19 [2] 12 18 [2] 09 1e [2] 15 19 [2] 09 36 }

  condition:
    any of them
}