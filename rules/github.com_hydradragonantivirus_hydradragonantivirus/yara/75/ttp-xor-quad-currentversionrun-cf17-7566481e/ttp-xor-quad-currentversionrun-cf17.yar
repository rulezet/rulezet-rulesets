rule TTP_XOR_QUAD_CurrentVersionRun_cf17 {
  strings:
    $key_cf17 = { 9c 78 [2] b8 76 [2] 93 5a [2] bd 78 [2] a9 63 [2] a6 79 [2] b8 64 [2] ba 65 [2] a1 63 [2] bd 64 [2] a1 4b }

  condition:
    any of them
}