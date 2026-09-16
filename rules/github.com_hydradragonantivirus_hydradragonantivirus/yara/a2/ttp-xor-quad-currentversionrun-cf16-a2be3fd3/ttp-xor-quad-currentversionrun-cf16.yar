rule TTP_XOR_QUAD_CurrentVersionRun_cf16 {
  strings:
    $key_cf16 = { 9c 79 [2] b8 77 [2] 93 5b [2] bd 79 [2] a9 62 [2] a6 78 [2] b8 65 [2] ba 64 [2] a1 62 [2] bd 65 [2] a1 4a }

  condition:
    any of them
}