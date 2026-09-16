rule TTP_XOR_QUAD_CurrentVersionRun_98d3 {
  strings:
    $key_98d3 = { cb bc [2] ef b2 [2] c4 9e [2] ea bc [2] fe a7 [2] f1 bd [2] ef a0 [2] ed a1 [2] f6 a7 [2] ea a0 [2] f6 8f }

  condition:
    any of them
}