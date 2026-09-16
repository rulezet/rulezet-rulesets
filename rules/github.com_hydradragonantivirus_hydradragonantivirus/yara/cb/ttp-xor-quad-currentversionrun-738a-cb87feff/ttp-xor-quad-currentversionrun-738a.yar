rule TTP_XOR_QUAD_CurrentVersionRun_738a {
  strings:
    $key_738a = { 20 e5 [2] 04 eb [2] 2f c7 [2] 01 e5 [2] 15 fe [2] 1a e4 [2] 04 f9 [2] 06 f8 [2] 1d fe [2] 01 f9 [2] 1d d6 }

  condition:
    any of them
}