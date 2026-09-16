rule TTP_XOR_QUAD_CurrentVersionRun_394a {
  strings:
    $key_394a = { 6a 25 [2] 4e 2b [2] 65 07 [2] 4b 25 [2] 5f 3e [2] 50 24 [2] 4e 39 [2] 4c 38 [2] 57 3e [2] 4b 39 [2] 57 16 }

  condition:
    any of them
}