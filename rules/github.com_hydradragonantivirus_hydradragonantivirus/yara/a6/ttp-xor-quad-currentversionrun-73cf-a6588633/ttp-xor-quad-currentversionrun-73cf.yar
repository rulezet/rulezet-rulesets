rule TTP_XOR_QUAD_CurrentVersionRun_73cf {
  strings:
    $key_73cf = { 20 a0 [2] 04 ae [2] 2f 82 [2] 01 a0 [2] 15 bb [2] 1a a1 [2] 04 bc [2] 06 bd [2] 1d bb [2] 01 bc [2] 1d 93 }

  condition:
    any of them
}