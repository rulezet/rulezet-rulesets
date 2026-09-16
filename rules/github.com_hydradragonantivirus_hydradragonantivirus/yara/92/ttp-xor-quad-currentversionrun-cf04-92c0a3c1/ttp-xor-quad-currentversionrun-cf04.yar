rule TTP_XOR_QUAD_CurrentVersionRun_cf04 {
  strings:
    $key_cf04 = { 9c 6b [2] b8 65 [2] 93 49 [2] bd 6b [2] a9 70 [2] a6 6a [2] b8 77 [2] ba 76 [2] a1 70 [2] bd 77 [2] a1 58 }

  condition:
    any of them
}