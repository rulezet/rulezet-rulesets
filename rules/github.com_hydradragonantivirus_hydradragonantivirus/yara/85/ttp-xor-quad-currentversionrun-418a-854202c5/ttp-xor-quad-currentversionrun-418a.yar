rule TTP_XOR_QUAD_CurrentVersionRun_418a {
  strings:
    $key_418a = { 12 e5 [2] 36 eb [2] 1d c7 [2] 33 e5 [2] 27 fe [2] 28 e4 [2] 36 f9 [2] 34 f8 [2] 2f fe [2] 33 f9 [2] 2f d6 }

  condition:
    any of them
}