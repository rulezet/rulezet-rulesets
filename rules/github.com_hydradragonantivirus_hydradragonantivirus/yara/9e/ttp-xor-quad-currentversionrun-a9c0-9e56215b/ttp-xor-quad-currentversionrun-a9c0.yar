rule TTP_XOR_QUAD_CurrentVersionRun_a9c0 {
  strings:
    $key_a9c0 = { fa af [2] de a1 [2] f5 8d [2] db af [2] cf b4 [2] c0 ae [2] de b3 [2] dc b2 [2] c7 b4 [2] db b3 [2] c7 9c }

  condition:
    any of them
}