rule TTP_XOR_QUAD_CurrentVersionRun_0f8a {
  strings:
    $key_0f8a = { 5c e5 [2] 78 eb [2] 53 c7 [2] 7d e5 [2] 69 fe [2] 66 e4 [2] 78 f9 [2] 7a f8 [2] 61 fe [2] 7d f9 [2] 61 d6 }

  condition:
    any of them
}