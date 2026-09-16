rule TTP_XOR_QUAD_CurrentVersionRun_98c3 {
  strings:
    $key_98c3 = { cb ac [2] ef a2 [2] c4 8e [2] ea ac [2] fe b7 [2] f1 ad [2] ef b0 [2] ed b1 [2] f6 b7 [2] ea b0 [2] f6 9f }

  condition:
    any of them
}