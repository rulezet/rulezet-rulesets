rule TTP_XOR_QUAD_CurrentVersionRun_d435 {
  strings:
    $key_d435 = { 87 5a [2] a3 54 [2] 88 78 [2] a6 5a [2] b2 41 [2] bd 5b [2] a3 46 [2] a1 47 [2] ba 41 [2] a6 46 [2] ba 69 }

  condition:
    any of them
}