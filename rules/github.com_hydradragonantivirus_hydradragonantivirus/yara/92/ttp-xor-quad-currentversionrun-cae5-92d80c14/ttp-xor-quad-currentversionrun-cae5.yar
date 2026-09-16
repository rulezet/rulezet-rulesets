rule TTP_XOR_QUAD_CurrentVersionRun_cae5 {
  strings:
    $key_cae5 = { 99 8a [2] bd 84 [2] 96 a8 [2] b8 8a [2] ac 91 [2] a3 8b [2] bd 96 [2] bf 97 [2] a4 91 [2] b8 96 [2] a4 b9 }

  condition:
    any of them
}