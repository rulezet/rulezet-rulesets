rule TTP_XOR_QUAD_CurrentVersionRun_d358 {
  strings:
    $key_d358 = { 80 37 [2] a4 39 [2] 8f 15 [2] a1 37 [2] b5 2c [2] ba 36 [2] a4 2b [2] a6 2a [2] bd 2c [2] a1 2b [2] bd 04 }

  condition:
    any of them
}