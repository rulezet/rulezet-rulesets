rule TTP_XOR_QUAD_CurrentVersionRun_aedf {
  strings:
    $key_aedf = { fd b0 [2] d9 be [2] f2 92 [2] dc b0 [2] c8 ab [2] c7 b1 [2] d9 ac [2] db ad [2] c0 ab [2] dc ac [2] c0 83 }

  condition:
    any of them
}