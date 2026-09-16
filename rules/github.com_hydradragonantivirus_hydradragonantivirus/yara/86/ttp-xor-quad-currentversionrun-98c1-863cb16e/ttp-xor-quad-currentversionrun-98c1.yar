rule TTP_XOR_QUAD_CurrentVersionRun_98c1 {
  strings:
    $key_98c1 = { cb ae [2] ef a0 [2] c4 8c [2] ea ae [2] fe b5 [2] f1 af [2] ef b2 [2] ed b3 [2] f6 b5 [2] ea b2 [2] f6 9d }

  condition:
    any of them
}