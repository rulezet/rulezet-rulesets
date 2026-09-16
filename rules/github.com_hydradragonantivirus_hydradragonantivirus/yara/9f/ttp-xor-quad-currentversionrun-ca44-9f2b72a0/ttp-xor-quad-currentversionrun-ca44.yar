rule TTP_XOR_QUAD_CurrentVersionRun_ca44 {
  strings:
    $key_ca44 = { 99 2b [2] bd 25 [2] 96 09 [2] b8 2b [2] ac 30 [2] a3 2a [2] bd 37 [2] bf 36 [2] a4 30 [2] b8 37 [2] a4 18 }

  condition:
    any of them
}