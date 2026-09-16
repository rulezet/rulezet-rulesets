rule TTP_XOR_QUAD_CurrentVersionRun_98d8 {
  strings:
    $key_98d8 = { cb b7 [2] ef b9 [2] c4 95 [2] ea b7 [2] fe ac [2] f1 b6 [2] ef ab [2] ed aa [2] f6 ac [2] ea ab [2] f6 84 }

  condition:
    any of them
}