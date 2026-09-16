rule TTP_XOR_QUAD_CurrentVersionRun_cf26 {
  strings:
    $key_cf26 = { 9c 49 [2] b8 47 [2] 93 6b [2] bd 49 [2] a9 52 [2] a6 48 [2] b8 55 [2] ba 54 [2] a1 52 [2] bd 55 [2] a1 7a }

  condition:
    any of them
}