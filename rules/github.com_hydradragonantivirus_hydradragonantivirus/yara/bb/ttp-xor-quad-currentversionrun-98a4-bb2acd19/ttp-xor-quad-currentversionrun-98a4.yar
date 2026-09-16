rule TTP_XOR_QUAD_CurrentVersionRun_98a4 {
  strings:
    $key_98a4 = { cb cb [2] ef c5 [2] c4 e9 [2] ea cb [2] fe d0 [2] f1 ca [2] ef d7 [2] ed d6 [2] f6 d0 [2] ea d7 [2] f6 f8 }

  condition:
    any of them
}