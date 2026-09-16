rule TTP_XOR_QUAD_CurrentVersionRun_f18a {
  strings:
    $key_f18a = { a2 e5 [2] 86 eb [2] ad c7 [2] 83 e5 [2] 97 fe [2] 98 e4 [2] 86 f9 [2] 84 f8 [2] 9f fe [2] 83 f9 [2] 9f d6 }

  condition:
    any of them
}