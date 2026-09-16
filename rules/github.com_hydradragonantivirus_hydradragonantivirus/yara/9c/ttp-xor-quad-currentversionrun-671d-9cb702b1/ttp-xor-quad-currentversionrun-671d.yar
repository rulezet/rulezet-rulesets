rule TTP_XOR_QUAD_CurrentVersionRun_671d {
  strings:
    $key_671d = { 34 72 [2] 10 7c [2] 3b 50 [2] 15 72 [2] 01 69 [2] 0e 73 [2] 10 6e [2] 12 6f [2] 09 69 [2] 15 6e [2] 09 41 }

  condition:
    any of them
}