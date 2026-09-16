rule TTP_XOR_QUAD_CurrentVersionRun_39ad {
  strings:
    $key_39ad = { 6a c2 [2] 4e cc [2] 65 e0 [2] 4b c2 [2] 5f d9 [2] 50 c3 [2] 4e de [2] 4c df [2] 57 d9 [2] 4b de [2] 57 f1 }

  condition:
    any of them
}