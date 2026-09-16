rule TTP_XOR_QUAD_CurrentVersionRun_a99a {
  strings:
    $key_a99a = { fa f5 [2] de fb [2] f5 d7 [2] db f5 [2] cf ee [2] c0 f4 [2] de e9 [2] dc e8 [2] c7 ee [2] db e9 [2] c7 c6 }

  condition:
    any of them
}