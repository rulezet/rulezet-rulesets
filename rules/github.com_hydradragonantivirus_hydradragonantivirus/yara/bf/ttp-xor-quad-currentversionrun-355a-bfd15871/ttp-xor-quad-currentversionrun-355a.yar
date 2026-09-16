rule TTP_XOR_QUAD_CurrentVersionRun_355a {
  strings:
    $key_355a = { 66 35 [2] 42 3b [2] 69 17 [2] 47 35 [2] 53 2e [2] 5c 34 [2] 42 29 [2] 40 28 [2] 5b 2e [2] 47 29 [2] 5b 06 }

  condition:
    any of them
}