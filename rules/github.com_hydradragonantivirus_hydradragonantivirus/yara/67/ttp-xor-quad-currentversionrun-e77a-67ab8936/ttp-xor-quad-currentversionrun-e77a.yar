rule TTP_XOR_QUAD_CurrentVersionRun_e77a {
  strings:
    $key_e77a = { b4 15 [2] 90 1b [2] bb 37 [2] 95 15 [2] 81 0e [2] 8e 14 [2] 90 09 [2] 92 08 [2] 89 0e [2] 95 09 [2] 89 26 }

  condition:
    any of them
}