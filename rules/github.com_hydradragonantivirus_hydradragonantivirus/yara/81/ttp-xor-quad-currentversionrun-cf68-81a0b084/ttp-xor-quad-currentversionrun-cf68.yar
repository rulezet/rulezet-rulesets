rule TTP_XOR_QUAD_CurrentVersionRun_cf68 {
  strings:
    $key_cf68 = { 9c 07 [2] b8 09 [2] 93 25 [2] bd 07 [2] a9 1c [2] a6 06 [2] b8 1b [2] ba 1a [2] a1 1c [2] bd 1b [2] a1 34 }

  condition:
    any of them
}