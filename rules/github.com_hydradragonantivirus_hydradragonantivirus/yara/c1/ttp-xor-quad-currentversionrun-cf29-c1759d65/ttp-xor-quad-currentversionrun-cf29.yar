rule TTP_XOR_QUAD_CurrentVersionRun_cf29 {
  strings:
    $key_cf29 = { 9c 46 [2] b8 48 [2] 93 64 [2] bd 46 [2] a9 5d [2] a6 47 [2] b8 5a [2] ba 5b [2] a1 5d [2] bd 5a [2] a1 75 }

  condition:
    any of them
}