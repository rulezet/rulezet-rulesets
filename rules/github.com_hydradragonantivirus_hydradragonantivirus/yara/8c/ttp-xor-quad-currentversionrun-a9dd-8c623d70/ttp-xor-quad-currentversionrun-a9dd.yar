rule TTP_XOR_QUAD_CurrentVersionRun_a9dd {
  strings:
    $key_a9dd = { fa b2 [2] de bc [2] f5 90 [2] db b2 [2] cf a9 [2] c0 b3 [2] de ae [2] dc af [2] c7 a9 [2] db ae [2] c7 81 }

  condition:
    any of them
}