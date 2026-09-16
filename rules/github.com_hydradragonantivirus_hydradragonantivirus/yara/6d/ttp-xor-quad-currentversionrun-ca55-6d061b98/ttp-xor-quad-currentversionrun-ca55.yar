rule TTP_XOR_QUAD_CurrentVersionRun_ca55 {
  strings:
    $key_ca55 = { 99 3a [2] bd 34 [2] 96 18 [2] b8 3a [2] ac 21 [2] a3 3b [2] bd 26 [2] bf 27 [2] a4 21 [2] b8 26 [2] a4 09 }

  condition:
    any of them
}