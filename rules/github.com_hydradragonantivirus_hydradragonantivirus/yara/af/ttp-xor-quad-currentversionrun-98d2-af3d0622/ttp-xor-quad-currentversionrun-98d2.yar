rule TTP_XOR_QUAD_CurrentVersionRun_98d2 {
  strings:
    $key_98d2 = { cb bd [2] ef b3 [2] c4 9f [2] ea bd [2] fe a6 [2] f1 bc [2] ef a1 [2] ed a0 [2] f6 a6 [2] ea a1 [2] f6 8e }

  condition:
    any of them
}