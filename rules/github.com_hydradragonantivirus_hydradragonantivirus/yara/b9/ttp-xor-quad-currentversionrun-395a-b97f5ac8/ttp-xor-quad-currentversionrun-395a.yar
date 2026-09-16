rule TTP_XOR_QUAD_CurrentVersionRun_395a {
  strings:
    $key_395a = { 6a 35 [2] 4e 3b [2] 65 17 [2] 4b 35 [2] 5f 2e [2] 50 34 [2] 4e 29 [2] 4c 28 [2] 57 2e [2] 4b 29 [2] 57 06 }

  condition:
    any of them
}