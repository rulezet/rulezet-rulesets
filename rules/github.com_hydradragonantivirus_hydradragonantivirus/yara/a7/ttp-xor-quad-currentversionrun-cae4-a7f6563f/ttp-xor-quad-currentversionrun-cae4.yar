rule TTP_XOR_QUAD_CurrentVersionRun_cae4 {
  strings:
    $key_cae4 = { 99 8b [2] bd 85 [2] 96 a9 [2] b8 8b [2] ac 90 [2] a3 8a [2] bd 97 [2] bf 96 [2] a4 90 [2] b8 97 [2] a4 b8 }

  condition:
    any of them
}