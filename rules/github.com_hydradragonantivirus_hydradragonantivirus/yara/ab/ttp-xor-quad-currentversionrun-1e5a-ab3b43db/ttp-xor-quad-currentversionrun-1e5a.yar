rule TTP_XOR_QUAD_CurrentVersionRun_1e5a {
  strings:
    $key_1e5a = { 4d 35 [2] 69 3b [2] 42 17 [2] 6c 35 [2] 78 2e [2] 77 34 [2] 69 29 [2] 6b 28 [2] 70 2e [2] 6c 29 [2] 70 06 }

  condition:
    any of them
}