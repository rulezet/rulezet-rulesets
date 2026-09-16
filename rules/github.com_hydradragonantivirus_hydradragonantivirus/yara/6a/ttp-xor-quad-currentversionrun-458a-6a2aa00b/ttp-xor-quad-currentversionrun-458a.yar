rule TTP_XOR_QUAD_CurrentVersionRun_458a {
  strings:
    $key_458a = { 16 e5 [2] 32 eb [2] 19 c7 [2] 37 e5 [2] 23 fe [2] 2c e4 [2] 32 f9 [2] 30 f8 [2] 2b fe [2] 37 f9 [2] 2b d6 }

  condition:
    any of them
}