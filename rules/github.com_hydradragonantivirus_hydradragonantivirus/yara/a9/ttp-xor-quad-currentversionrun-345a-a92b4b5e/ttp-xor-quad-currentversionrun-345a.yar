rule TTP_XOR_QUAD_CurrentVersionRun_345a {
  strings:
    $key_345a = { 67 35 [2] 43 3b [2] 68 17 [2] 46 35 [2] 52 2e [2] 5d 34 [2] 43 29 [2] 41 28 [2] 5a 2e [2] 46 29 [2] 5a 06 }

  condition:
    any of them
}