rule TTP_XOR_QUAD_CurrentVersionRun_d444 {
  strings:
    $key_d444 = { 87 2b [2] a3 25 [2] 88 09 [2] a6 2b [2] b2 30 [2] bd 2a [2] a3 37 [2] a1 36 [2] ba 30 [2] a6 37 [2] ba 18 }

  condition:
    any of them
}