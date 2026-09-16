rule TTP_XOR_QUAD_CurrentVersionRun_d334 {
  strings:
    $key_d334 = { 80 5b [2] a4 55 [2] 8f 79 [2] a1 5b [2] b5 40 [2] ba 5a [2] a4 47 [2] a6 46 [2] bd 40 [2] a1 47 [2] bd 68 }

  condition:
    any of them
}