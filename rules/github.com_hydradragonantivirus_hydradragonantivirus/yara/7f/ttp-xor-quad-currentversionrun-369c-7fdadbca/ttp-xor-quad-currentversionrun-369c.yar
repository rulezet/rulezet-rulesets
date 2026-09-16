rule TTP_XOR_QUAD_CurrentVersionRun_369c {
  strings:
    $key_369c = { 65 f3 [2] 41 fd [2] 6a d1 [2] 44 f3 [2] 50 e8 [2] 5f f2 [2] 41 ef [2] 43 ee [2] 58 e8 [2] 44 ef [2] 58 c0 }

  condition:
    any of them
}