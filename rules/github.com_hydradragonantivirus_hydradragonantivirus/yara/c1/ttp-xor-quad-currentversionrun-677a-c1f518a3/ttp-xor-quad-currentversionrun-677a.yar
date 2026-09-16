rule TTP_XOR_QUAD_CurrentVersionRun_677a {
  strings:
    $key_677a = { 34 15 [2] 10 1b [2] 3b 37 [2] 15 15 [2] 01 0e [2] 0e 14 [2] 10 09 [2] 12 08 [2] 09 0e [2] 15 09 [2] 09 26 }

  condition:
    any of them
}