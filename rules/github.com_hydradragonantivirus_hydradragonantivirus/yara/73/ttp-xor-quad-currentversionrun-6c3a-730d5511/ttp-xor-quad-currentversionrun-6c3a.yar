rule TTP_XOR_QUAD_CurrentVersionRun_6c3a {
  strings:
    $key_6c3a = { 3f 55 [2] 1b 5b [2] 30 77 [2] 1e 55 [2] 0a 4e [2] 05 54 [2] 1b 49 [2] 19 48 [2] 02 4e [2] 1e 49 [2] 02 66 }

  condition:
    any of them
}