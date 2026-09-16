rule TTP_XOR_QUAD_CurrentVersionRun_aade {
  strings:
    $key_aade = { f9 b1 [2] dd bf [2] f6 93 [2] d8 b1 [2] cc aa [2] c3 b0 [2] dd ad [2] df ac [2] c4 aa [2] d8 ad [2] c4 82 }

  condition:
    any of them
}