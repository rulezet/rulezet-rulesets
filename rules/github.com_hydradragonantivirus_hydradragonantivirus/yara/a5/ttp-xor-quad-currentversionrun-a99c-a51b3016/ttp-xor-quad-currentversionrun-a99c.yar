rule TTP_XOR_QUAD_CurrentVersionRun_a99c {
  strings:
    $key_a99c = { fa f3 [2] de fd [2] f5 d1 [2] db f3 [2] cf e8 [2] c0 f2 [2] de ef [2] dc ee [2] c7 e8 [2] db ef [2] c7 c0 }

  condition:
    any of them
}