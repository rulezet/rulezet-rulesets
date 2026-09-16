rule TTP_XOR_QUAD_CurrentVersionRun_435a {
  strings:
    $key_435a = { 10 35 [2] 34 3b [2] 1f 17 [2] 31 35 [2] 25 2e [2] 2a 34 [2] 34 29 [2] 36 28 [2] 2d 2e [2] 31 29 [2] 2d 06 }

  condition:
    any of them
}