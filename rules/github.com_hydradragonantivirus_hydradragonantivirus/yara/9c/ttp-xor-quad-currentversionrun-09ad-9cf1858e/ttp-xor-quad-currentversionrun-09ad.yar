rule TTP_XOR_QUAD_CurrentVersionRun_09ad {
  strings:
    $key_09ad = { 5a c2 [2] 7e cc [2] 55 e0 [2] 7b c2 [2] 6f d9 [2] 60 c3 [2] 7e de [2] 7c df [2] 67 d9 [2] 7b de [2] 67 f1 }

  condition:
    any of them
}