rule TTP_XOR_QUAD_CurrentVersionRun_561d {
  strings:
    $key_561d = { 05 72 [2] 21 7c [2] 0a 50 [2] 24 72 [2] 30 69 [2] 3f 73 [2] 21 6e [2] 23 6f [2] 38 69 [2] 24 6e [2] 38 41 }

  condition:
    any of them
}