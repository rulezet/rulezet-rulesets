rule TTP_XOR_QUAD_CurrentVersionRun_2f3a {
  strings:
    $key_2f3a = { 7c 55 [2] 58 5b [2] 73 77 [2] 5d 55 [2] 49 4e [2] 46 54 [2] 58 49 [2] 5a 48 [2] 41 4e [2] 5d 49 [2] 41 66 }

  condition:
    any of them
}