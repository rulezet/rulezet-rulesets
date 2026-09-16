rule TTP_XOR_QUAD_CurrentVersionRun_d308 {
  strings:
    $key_d308 = { 80 67 [2] a4 69 [2] 8f 45 [2] a1 67 [2] b5 7c [2] ba 66 [2] a4 7b [2] a6 7a [2] bd 7c [2] a1 7b [2] bd 54 }

  condition:
    any of them
}