rule TTP_XOR_QUAD_CurrentVersionRun_ca1b {
  strings:
    $key_ca1b = { 99 74 [2] bd 7a [2] 96 56 [2] b8 74 [2] ac 6f [2] a3 75 [2] bd 68 [2] bf 69 [2] a4 6f [2] b8 68 [2] a4 47 }

  condition:
    any of them
}