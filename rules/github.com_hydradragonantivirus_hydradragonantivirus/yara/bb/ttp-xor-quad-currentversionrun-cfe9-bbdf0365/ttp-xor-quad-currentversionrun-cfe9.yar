rule TTP_XOR_QUAD_CurrentVersionRun_cfe9 {
  strings:
    $key_cfe9 = { 9c 86 [2] b8 88 [2] 93 a4 [2] bd 86 [2] a9 9d [2] a6 87 [2] b8 9a [2] ba 9b [2] a1 9d [2] bd 9a [2] a1 b5 }

  condition:
    any of them
}