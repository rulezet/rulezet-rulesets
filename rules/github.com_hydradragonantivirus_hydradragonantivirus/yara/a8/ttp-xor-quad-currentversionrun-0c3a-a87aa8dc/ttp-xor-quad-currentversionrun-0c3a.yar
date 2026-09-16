rule TTP_XOR_QUAD_CurrentVersionRun_0c3a {
  strings:
    $key_0c3a = { 5f 55 [2] 7b 5b [2] 50 77 [2] 7e 55 [2] 6a 4e [2] 65 54 [2] 7b 49 [2] 79 48 [2] 62 4e [2] 7e 49 [2] 62 66 }

  condition:
    any of them
}