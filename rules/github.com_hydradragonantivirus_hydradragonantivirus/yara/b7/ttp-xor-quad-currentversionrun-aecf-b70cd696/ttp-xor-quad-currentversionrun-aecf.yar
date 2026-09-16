rule TTP_XOR_QUAD_CurrentVersionRun_aecf {
  strings:
    $key_aecf = { fd a0 [2] d9 ae [2] f2 82 [2] dc a0 [2] c8 bb [2] c7 a1 [2] d9 bc [2] db bd [2] c0 bb [2] dc bc [2] c0 93 }

  condition:
    any of them
}