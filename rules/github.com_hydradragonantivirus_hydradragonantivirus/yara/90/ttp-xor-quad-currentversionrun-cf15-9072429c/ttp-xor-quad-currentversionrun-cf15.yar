rule TTP_XOR_QUAD_CurrentVersionRun_cf15 {
  strings:
    $key_cf15 = { 9c 7a [2] b8 74 [2] 93 58 [2] bd 7a [2] a9 61 [2] a6 7b [2] b8 66 [2] ba 67 [2] a1 61 [2] bd 66 [2] a1 49 }

  condition:
    any of them
}