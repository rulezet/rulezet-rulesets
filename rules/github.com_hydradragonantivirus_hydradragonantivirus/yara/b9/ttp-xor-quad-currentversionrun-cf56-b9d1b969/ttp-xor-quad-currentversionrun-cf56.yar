rule TTP_XOR_QUAD_CurrentVersionRun_cf56 {
  strings:
    $key_cf56 = { 9c 39 [2] b8 37 [2] 93 1b [2] bd 39 [2] a9 22 [2] a6 38 [2] b8 25 [2] ba 24 [2] a1 22 [2] bd 25 [2] a1 0a }

  condition:
    any of them
}