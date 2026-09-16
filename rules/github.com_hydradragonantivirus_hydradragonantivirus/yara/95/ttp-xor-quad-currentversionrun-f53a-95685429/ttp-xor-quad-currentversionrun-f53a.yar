rule TTP_XOR_QUAD_CurrentVersionRun_f53a {
  strings:
    $key_f53a = { a6 55 [2] 82 5b [2] a9 77 [2] 87 55 [2] 93 4e [2] 9c 54 [2] 82 49 [2] 80 48 [2] 9b 4e [2] 87 49 [2] 9b 66 }

  condition:
    any of them
}