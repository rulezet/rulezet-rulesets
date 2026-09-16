rule TTP_XOR_QUAD_CurrentVersionRun_d344 {
  strings:
    $key_d344 = { 80 2b [2] a4 25 [2] 8f 09 [2] a1 2b [2] b5 30 [2] ba 2a [2] a4 37 [2] a6 36 [2] bd 30 [2] a1 37 [2] bd 18 }

  condition:
    any of them
}