rule TTP_XOR_QUAD_CurrentVersionRun_283a {
  strings:
    $key_283a = { 7b 55 [2] 5f 5b [2] 74 77 [2] 5a 55 [2] 4e 4e [2] 41 54 [2] 5f 49 [2] 5d 48 [2] 46 4e [2] 5a 49 [2] 46 66 }

  condition:
    any of them
}