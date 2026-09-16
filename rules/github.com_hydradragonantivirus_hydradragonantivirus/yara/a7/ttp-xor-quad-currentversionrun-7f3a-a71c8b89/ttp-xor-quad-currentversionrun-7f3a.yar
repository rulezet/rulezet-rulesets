rule TTP_XOR_QUAD_CurrentVersionRun_7f3a {
  strings:
    $key_7f3a = { 2c 55 [2] 08 5b [2] 23 77 [2] 0d 55 [2] 19 4e [2] 16 54 [2] 08 49 [2] 0a 48 [2] 11 4e [2] 0d 49 [2] 11 66 }

  condition:
    any of them
}