rule TTP_XOR_QUAD_CurrentVersionRun_798a {
  strings:
    $key_798a = { 2a e5 [2] 0e eb [2] 25 c7 [2] 0b e5 [2] 1f fe [2] 10 e4 [2] 0e f9 [2] 0c f8 [2] 17 fe [2] 0b f9 [2] 17 d6 }

  condition:
    any of them
}