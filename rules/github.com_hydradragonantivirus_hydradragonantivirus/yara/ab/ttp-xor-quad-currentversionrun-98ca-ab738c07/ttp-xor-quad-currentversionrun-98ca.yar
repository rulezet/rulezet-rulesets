rule TTP_XOR_QUAD_CurrentVersionRun_98ca {
  strings:
    $key_98ca = { cb a5 [2] ef ab [2] c4 87 [2] ea a5 [2] fe be [2] f1 a4 [2] ef b9 [2] ed b8 [2] f6 be [2] ea b9 [2] f6 96 }

  condition:
    any of them
}