rule TTP_XOR_QUAD_CurrentVersionRun_2a3a {
  strings:
    $key_2a3a = { 79 55 [2] 5d 5b [2] 76 77 [2] 58 55 [2] 4c 4e [2] 43 54 [2] 5d 49 [2] 5f 48 [2] 44 4e [2] 58 49 [2] 44 66 }

  condition:
    any of them
}