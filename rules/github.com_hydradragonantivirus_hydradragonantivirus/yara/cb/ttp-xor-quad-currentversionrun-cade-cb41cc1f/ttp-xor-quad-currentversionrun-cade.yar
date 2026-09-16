rule TTP_XOR_QUAD_CurrentVersionRun_cade {
  strings:
    $key_cade = { 99 b1 [2] bd bf [2] 96 93 [2] b8 b1 [2] ac aa [2] a3 b0 [2] bd ad [2] bf ac [2] a4 aa [2] b8 ad [2] a4 82 }

  condition:
    any of them
}