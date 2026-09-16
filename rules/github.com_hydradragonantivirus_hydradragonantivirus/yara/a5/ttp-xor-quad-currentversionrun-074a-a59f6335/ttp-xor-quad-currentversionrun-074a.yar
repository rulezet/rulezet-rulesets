rule TTP_XOR_QUAD_CurrentVersionRun_074a {
  strings:
    $key_074a = { 54 25 [2] 70 2b [2] 5b 07 [2] 75 25 [2] 61 3e [2] 6e 24 [2] 70 39 [2] 72 38 [2] 69 3e [2] 75 39 [2] 69 16 }

  condition:
    any of them
}