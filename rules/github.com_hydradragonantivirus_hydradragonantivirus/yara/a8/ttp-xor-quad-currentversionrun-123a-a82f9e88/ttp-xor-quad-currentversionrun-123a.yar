rule TTP_XOR_QUAD_CurrentVersionRun_123a {
  strings:
    $key_123a = { 41 55 [2] 65 5b [2] 4e 77 [2] 60 55 [2] 74 4e [2] 7b 54 [2] 65 49 [2] 67 48 [2] 7c 4e [2] 60 49 [2] 7c 66 }

  condition:
    any of them
}