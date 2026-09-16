rule TTP_XOR_QUAD_CurrentVersionRun_558a {
  strings:
    $key_558a = { 06 e5 [2] 22 eb [2] 09 c7 [2] 27 e5 [2] 33 fe [2] 3c e4 [2] 22 f9 [2] 20 f8 [2] 3b fe [2] 27 f9 [2] 3b d6 }

  condition:
    any of them
}