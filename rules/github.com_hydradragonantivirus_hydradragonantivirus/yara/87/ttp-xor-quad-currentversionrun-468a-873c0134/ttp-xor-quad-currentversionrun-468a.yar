rule TTP_XOR_QUAD_CurrentVersionRun_468a {
  strings:
    $key_468a = { 15 e5 [2] 31 eb [2] 1a c7 [2] 34 e5 [2] 20 fe [2] 2f e4 [2] 31 f9 [2] 33 f8 [2] 28 fe [2] 34 f9 [2] 28 d6 }

  condition:
    any of them
}