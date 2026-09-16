rule TTP_XOR_QUAD_CurrentVersionRun_d434 {
  strings:
    $key_d434 = { 87 5b [2] a3 55 [2] 88 79 [2] a6 5b [2] b2 40 [2] bd 5a [2] a3 47 [2] a1 46 [2] ba 40 [2] a6 47 [2] ba 68 }

  condition:
    any of them
}