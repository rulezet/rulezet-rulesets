rule TTP_XOR_QUAD_CurrentVersionRun_4e3a {
  strings:
    $key_4e3a = { 1d 55 [2] 39 5b [2] 12 77 [2] 3c 55 [2] 28 4e [2] 27 54 [2] 39 49 [2] 3b 48 [2] 20 4e [2] 3c 49 [2] 20 66 }

  condition:
    any of them
}