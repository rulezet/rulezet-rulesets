rule TTP_XOR_QUAD_CurrentVersionRun_1b3a {
  strings:
    $key_1b3a = { 48 55 [2] 6c 5b [2] 47 77 [2] 69 55 [2] 7d 4e [2] 72 54 [2] 6c 49 [2] 6e 48 [2] 75 4e [2] 69 49 [2] 75 66 }

  condition:
    any of them
}