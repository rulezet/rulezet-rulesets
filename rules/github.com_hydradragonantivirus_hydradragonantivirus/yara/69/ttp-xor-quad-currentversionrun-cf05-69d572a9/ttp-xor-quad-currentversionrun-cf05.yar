rule TTP_XOR_QUAD_CurrentVersionRun_cf05 {
  strings:
    $key_cf05 = { 9c 6a [2] b8 64 [2] 93 48 [2] bd 6a [2] a9 71 [2] a6 6b [2] b8 76 [2] ba 77 [2] a1 71 [2] bd 76 [2] a1 59 }

  condition:
    any of them
}