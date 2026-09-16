rule TTP_XOR_QUAD_CurrentVersionRun_2b3a {
  strings:
    $key_2b3a = { 78 55 [2] 5c 5b [2] 77 77 [2] 59 55 [2] 4d 4e [2] 42 54 [2] 5c 49 [2] 5e 48 [2] 45 4e [2] 59 49 [2] 45 66 }

  condition:
    any of them
}