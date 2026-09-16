rule TTP_XOR_QUAD_CurrentVersionRun_b08a {
  strings:
    $key_b08a = { e3 e5 [2] c7 eb [2] ec c7 [2] c2 e5 [2] d6 fe [2] d9 e4 [2] c7 f9 [2] c5 f8 [2] de fe [2] c2 f9 [2] de d6 }

  condition:
    any of them
}