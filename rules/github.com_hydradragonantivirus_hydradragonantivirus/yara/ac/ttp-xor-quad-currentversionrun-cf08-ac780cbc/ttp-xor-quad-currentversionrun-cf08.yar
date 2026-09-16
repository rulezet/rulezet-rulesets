rule TTP_XOR_QUAD_CurrentVersionRun_cf08 {
  strings:
    $key_cf08 = { 9c 67 [2] b8 69 [2] 93 45 [2] bd 67 [2] a9 7c [2] a6 66 [2] b8 7b [2] ba 7a [2] a1 7c [2] bd 7b [2] a1 54 }

  condition:
    any of them
}