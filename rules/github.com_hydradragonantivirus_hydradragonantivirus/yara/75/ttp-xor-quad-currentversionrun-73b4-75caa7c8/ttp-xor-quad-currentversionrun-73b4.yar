rule TTP_XOR_QUAD_CurrentVersionRun_73b4 {
  strings:
    $key_73b4 = { 20 db [2] 04 d5 [2] 2f f9 [2] 01 db [2] 15 c0 [2] 1a da [2] 04 c7 [2] 06 c6 [2] 1d c0 [2] 01 c7 [2] 1d e8 }

  condition:
    any of them
}