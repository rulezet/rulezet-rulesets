rule TTP_XOR_QUAD_CurrentVersionRun_49ad {
  strings:
    $key_49ad = { 1a c2 [2] 3e cc [2] 15 e0 [2] 3b c2 [2] 2f d9 [2] 20 c3 [2] 3e de [2] 3c df [2] 27 d9 [2] 3b de [2] 27 f1 }

  condition:
    any of them
}