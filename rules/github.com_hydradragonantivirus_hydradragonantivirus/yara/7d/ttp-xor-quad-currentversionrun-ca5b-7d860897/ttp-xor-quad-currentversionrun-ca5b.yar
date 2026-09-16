rule TTP_XOR_QUAD_CurrentVersionRun_ca5b {
  strings:
    $key_ca5b = { 99 34 [2] bd 3a [2] 96 16 [2] b8 34 [2] ac 2f [2] a3 35 [2] bd 28 [2] bf 29 [2] a4 2f [2] b8 28 [2] a4 07 }

  condition:
    any of them
}