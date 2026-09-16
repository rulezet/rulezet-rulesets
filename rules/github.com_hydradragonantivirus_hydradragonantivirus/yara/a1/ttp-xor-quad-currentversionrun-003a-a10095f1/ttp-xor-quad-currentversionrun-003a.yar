rule TTP_XOR_QUAD_CurrentVersionRun_003a {
  strings:
    $key_003a = { 53 55 [2] 77 5b [2] 5c 77 [2] 72 55 [2] 66 4e [2] 69 54 [2] 77 49 [2] 75 48 [2] 6e 4e [2] 72 49 [2] 6e 66 }

  condition:
    any of them
}