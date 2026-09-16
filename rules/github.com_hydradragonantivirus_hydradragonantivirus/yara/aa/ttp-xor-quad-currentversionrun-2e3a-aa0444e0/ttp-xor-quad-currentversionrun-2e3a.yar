rule TTP_XOR_QUAD_CurrentVersionRun_2e3a {
  strings:
    $key_2e3a = { 7d 55 [2] 59 5b [2] 72 77 [2] 5c 55 [2] 48 4e [2] 47 54 [2] 59 49 [2] 5b 48 [2] 40 4e [2] 5c 49 [2] 40 66 }

  condition:
    any of them
}