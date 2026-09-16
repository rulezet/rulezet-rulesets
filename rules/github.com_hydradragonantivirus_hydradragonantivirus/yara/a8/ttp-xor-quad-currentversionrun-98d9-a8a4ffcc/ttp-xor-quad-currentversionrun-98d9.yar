rule TTP_XOR_QUAD_CurrentVersionRun_98d9 {
  strings:
    $key_98d9 = { cb b6 [2] ef b8 [2] c4 94 [2] ea b6 [2] fe ad [2] f1 b7 [2] ef aa [2] ed ab [2] f6 ad [2] ea aa [2] f6 85 }

  condition:
    any of them
}