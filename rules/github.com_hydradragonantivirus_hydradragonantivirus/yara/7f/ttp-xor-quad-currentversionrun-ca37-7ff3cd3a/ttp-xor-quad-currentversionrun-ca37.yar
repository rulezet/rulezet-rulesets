rule TTP_XOR_QUAD_CurrentVersionRun_ca37 {
  strings:
    $key_ca37 = { 99 58 [2] bd 56 [2] 96 7a [2] b8 58 [2] ac 43 [2] a3 59 [2] bd 44 [2] bf 45 [2] a4 43 [2] b8 44 [2] a4 6b }

  condition:
    any of them
}