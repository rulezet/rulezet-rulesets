rule TTP_XOR_QUAD_CurrentVersionRun_caf4 {
  strings:
    $key_caf4 = { 99 9b [2] bd 95 [2] 96 b9 [2] b8 9b [2] ac 80 [2] a3 9a [2] bd 87 [2] bf 86 [2] a4 80 [2] b8 87 [2] a4 a8 }

  condition:
    any of them
}