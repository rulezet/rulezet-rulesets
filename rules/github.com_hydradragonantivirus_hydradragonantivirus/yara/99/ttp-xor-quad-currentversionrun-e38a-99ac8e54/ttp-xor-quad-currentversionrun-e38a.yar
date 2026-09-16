rule TTP_XOR_QUAD_CurrentVersionRun_e38a {
  strings:
    $key_e38a = { b0 e5 [2] 94 eb [2] bf c7 [2] 91 e5 [2] 85 fe [2] 8a e4 [2] 94 f9 [2] 96 f8 [2] 8d fe [2] 91 f9 [2] 8d d6 }

  condition:
    any of them
}