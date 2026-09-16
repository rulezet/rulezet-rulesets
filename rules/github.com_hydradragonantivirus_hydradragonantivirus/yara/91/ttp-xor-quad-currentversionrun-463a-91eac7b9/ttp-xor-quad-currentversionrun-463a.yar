rule TTP_XOR_QUAD_CurrentVersionRun_463a {
  strings:
    $key_463a = { 15 55 [2] 31 5b [2] 1a 77 [2] 34 55 [2] 20 4e [2] 2f 54 [2] 31 49 [2] 33 48 [2] 28 4e [2] 34 49 [2] 28 66 }

  condition:
    any of them
}