rule TTP_XOR_QUAD_CurrentVersionRun_d314 {
  strings:
    $key_d314 = { 80 7b [2] a4 75 [2] 8f 59 [2] a1 7b [2] b5 60 [2] ba 7a [2] a4 67 [2] a6 66 [2] bd 60 [2] a1 67 [2] bd 48 }

  condition:
    any of them
}