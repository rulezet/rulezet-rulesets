rule TTP_XOR_QUAD_CurrentVersionRun_cf0b {
  strings:
    $key_cf0b = { 9c 64 [2] b8 6a [2] 93 46 [2] bd 64 [2] a9 7f [2] a6 65 [2] b8 78 [2] ba 79 [2] a1 7f [2] bd 78 [2] a1 57 }

  condition:
    any of them
}