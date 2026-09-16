rule TTP_XOR_QUAD_CurrentVersionRun_004a {
  strings:
    $key_004a = { 53 25 [2] 77 2b [2] 5c 07 [2] 72 25 [2] 66 3e [2] 69 24 [2] 77 39 [2] 75 38 [2] 6e 3e [2] 72 39 [2] 6e 16 }

  condition:
    any of them
}