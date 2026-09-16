rule TTP_XOR_QUAD_CurrentVersionRun_cfe4 {
  strings:
    $key_cfe4 = { 9c 8b [2] b8 85 [2] 93 a9 [2] bd 8b [2] a9 90 [2] a6 8a [2] b8 97 [2] ba 96 [2] a1 90 [2] bd 97 [2] a1 b8 }

  condition:
    any of them
}