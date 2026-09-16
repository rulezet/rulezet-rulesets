rule TTP_XOR_QUAD_CurrentVersionRun_aacf {
  strings:
    $key_aacf = { f9 a0 [2] dd ae [2] f6 82 [2] d8 a0 [2] cc bb [2] c3 a1 [2] dd bc [2] df bd [2] c4 bb [2] d8 bc [2] c4 93 }

  condition:
    any of them
}