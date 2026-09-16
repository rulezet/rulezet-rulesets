rule TTP_XOR_QUAD_CurrentVersionRun_a9c5 {
  strings:
    $key_a9c5 = { fa aa [2] de a4 [2] f5 88 [2] db aa [2] cf b1 [2] c0 ab [2] de b6 [2] dc b7 [2] c7 b1 [2] db b6 [2] c7 99 }

  condition:
    any of them
}