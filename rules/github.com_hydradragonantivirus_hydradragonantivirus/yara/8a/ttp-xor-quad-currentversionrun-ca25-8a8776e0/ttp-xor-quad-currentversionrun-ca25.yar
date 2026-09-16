rule TTP_XOR_QUAD_CurrentVersionRun_ca25 {
  strings:
    $key_ca25 = { 99 4a [2] bd 44 [2] 96 68 [2] b8 4a [2] ac 51 [2] a3 4b [2] bd 56 [2] bf 57 [2] a4 51 [2] b8 56 [2] a4 79 }

  condition:
    any of them
}