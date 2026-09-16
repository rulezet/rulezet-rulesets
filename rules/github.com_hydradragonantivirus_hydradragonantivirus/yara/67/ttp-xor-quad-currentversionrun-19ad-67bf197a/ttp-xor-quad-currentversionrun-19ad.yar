rule TTP_XOR_QUAD_CurrentVersionRun_19ad {
  strings:
    $key_19ad = { 4a c2 [2] 6e cc [2] 45 e0 [2] 6b c2 [2] 7f d9 [2] 70 c3 [2] 6e de [2] 6c df [2] 77 d9 [2] 6b de [2] 77 f1 }

  condition:
    any of them
}