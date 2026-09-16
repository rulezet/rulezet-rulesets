rule TTP_XOR_QUAD_CurrentVersionRun_a9c4 {
  strings:
    $key_a9c4 = { fa ab [2] de a5 [2] f5 89 [2] db ab [2] cf b0 [2] c0 aa [2] de b7 [2] dc b6 [2] c7 b0 [2] db b7 [2] c7 98 }

  condition:
    any of them
}