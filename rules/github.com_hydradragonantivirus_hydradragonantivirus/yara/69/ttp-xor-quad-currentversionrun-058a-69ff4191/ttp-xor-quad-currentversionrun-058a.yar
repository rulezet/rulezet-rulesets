rule TTP_XOR_QUAD_CurrentVersionRun_058a {
  strings:
    $key_058a = { 56 e5 [2] 72 eb [2] 59 c7 [2] 77 e5 [2] 63 fe [2] 6c e4 [2] 72 f9 [2] 70 f8 [2] 6b fe [2] 77 f9 [2] 6b d6 }

  condition:
    any of them
}