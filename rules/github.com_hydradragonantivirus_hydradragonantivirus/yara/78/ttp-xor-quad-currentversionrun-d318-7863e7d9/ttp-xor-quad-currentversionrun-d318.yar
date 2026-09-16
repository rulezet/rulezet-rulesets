rule TTP_XOR_QUAD_CurrentVersionRun_d318 {
  strings:
    $key_d318 = { 80 77 [2] a4 79 [2] 8f 55 [2] a1 77 [2] b5 6c [2] ba 76 [2] a4 6b [2] a6 6a [2] bd 6c [2] a1 6b [2] bd 44 }

  condition:
    any of them
}