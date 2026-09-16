rule TTP_XOR_QUAD_CurrentVersionRun_caf5 {
  strings:
    $key_caf5 = { 99 9a [2] bd 94 [2] 96 b8 [2] b8 9a [2] ac 81 [2] a3 9b [2] bd 86 [2] bf 87 [2] a4 81 [2] b8 86 [2] a4 a9 }

  condition:
    any of them
}