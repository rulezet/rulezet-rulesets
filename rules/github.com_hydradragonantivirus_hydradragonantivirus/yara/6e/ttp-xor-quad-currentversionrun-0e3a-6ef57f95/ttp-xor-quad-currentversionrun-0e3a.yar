rule TTP_XOR_QUAD_CurrentVersionRun_0e3a {
  strings:
    $key_0e3a = { 5d 55 [2] 79 5b [2] 52 77 [2] 7c 55 [2] 68 4e [2] 67 54 [2] 79 49 [2] 7b 48 [2] 60 4e [2] 7c 49 [2] 60 66 }

  condition:
    any of them
}