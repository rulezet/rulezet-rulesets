rule TTP_XOR_QUAD_CurrentVersionRun_d419 {
  strings:
    $key_d419 = { 87 76 [2] a3 78 [2] 88 54 [2] a6 76 [2] b2 6d [2] bd 77 [2] a3 6a [2] a1 6b [2] ba 6d [2] a6 6a [2] ba 45 }

  condition:
    any of them
}