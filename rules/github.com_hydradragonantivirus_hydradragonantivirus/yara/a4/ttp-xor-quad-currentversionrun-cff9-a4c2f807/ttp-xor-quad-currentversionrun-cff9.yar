rule TTP_XOR_QUAD_CurrentVersionRun_cff9 {
  strings:
    $key_cff9 = { 9c 96 [2] b8 98 [2] 93 b4 [2] bd 96 [2] a9 8d [2] a6 97 [2] b8 8a [2] ba 8b [2] a1 8d [2] bd 8a [2] a1 a5 }

  condition:
    any of them
}