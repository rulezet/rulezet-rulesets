rule TTP_XOR_QUAD_CurrentVersionRun_d319 {
  strings:
    $key_d319 = { 80 76 [2] a4 78 [2] 8f 54 [2] a1 76 [2] b5 6d [2] ba 77 [2] a4 6a [2] a6 6b [2] bd 6d [2] a1 6a [2] bd 45 }

  condition:
    any of them
}