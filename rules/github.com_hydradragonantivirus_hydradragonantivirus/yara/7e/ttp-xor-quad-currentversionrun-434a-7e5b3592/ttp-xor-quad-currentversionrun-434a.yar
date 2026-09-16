rule TTP_XOR_QUAD_CurrentVersionRun_434a {
  strings:
    $key_434a = { 10 25 [2] 34 2b [2] 1f 07 [2] 31 25 [2] 25 3e [2] 2a 24 [2] 34 39 [2] 36 38 [2] 2d 3e [2] 31 39 [2] 2d 16 }

  condition:
    any of them
}