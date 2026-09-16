rule TTP_XOR_QUAD_CurrentVersionRun_cf35 {
  strings:
    $key_cf35 = { 9c 5a [2] b8 54 [2] 93 78 [2] bd 5a [2] a9 41 [2] a6 5b [2] b8 46 [2] ba 47 [2] a1 41 [2] bd 46 [2] a1 69 }

  condition:
    any of them
}