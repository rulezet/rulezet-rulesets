rule TTP_XOR_QUAD_CurrentVersionRun_0b3a {
  strings:
    $key_0b3a = { 58 55 [2] 7c 5b [2] 57 77 [2] 79 55 [2] 6d 4e [2] 62 54 [2] 7c 49 [2] 7e 48 [2] 65 4e [2] 79 49 [2] 65 66 }

  condition:
    any of them
}