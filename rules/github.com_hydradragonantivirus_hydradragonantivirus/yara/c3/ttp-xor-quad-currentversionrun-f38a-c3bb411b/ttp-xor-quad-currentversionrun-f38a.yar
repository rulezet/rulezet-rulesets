rule TTP_XOR_QUAD_CurrentVersionRun_f38a {
  strings:
    $key_f38a = { a0 e5 [2] 84 eb [2] af c7 [2] 81 e5 [2] 95 fe [2] 9a e4 [2] 84 f9 [2] 86 f8 [2] 9d fe [2] 81 f9 [2] 9d d6 }

  condition:
    any of them
}