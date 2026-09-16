rule TTP_XOR_QUAD_CurrentVersionRun_e63a {
  strings:
    $key_e63a = { b5 55 [2] 91 5b [2] ba 77 [2] 94 55 [2] 80 4e [2] 8f 54 [2] 91 49 [2] 93 48 [2] 88 4e [2] 94 49 [2] 88 66 }

  condition:
    any of them
}