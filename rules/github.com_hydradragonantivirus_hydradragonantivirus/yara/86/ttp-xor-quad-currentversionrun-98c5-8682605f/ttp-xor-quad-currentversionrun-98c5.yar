rule TTP_XOR_QUAD_CurrentVersionRun_98c5 {
  strings:
    $key_98c5 = { cb aa [2] ef a4 [2] c4 88 [2] ea aa [2] fe b1 [2] f1 ab [2] ef b6 [2] ed b7 [2] f6 b1 [2] ea b6 [2] f6 99 }

  condition:
    any of them
}