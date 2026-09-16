rule TTP_XOR_QUAD_CurrentVersionRun_438a {
  strings:
    $key_438a = { 10 e5 [2] 34 eb [2] 1f c7 [2] 31 e5 [2] 25 fe [2] 2a e4 [2] 34 f9 [2] 36 f8 [2] 2d fe [2] 31 f9 [2] 2d d6 }

  condition:
    any of them
}