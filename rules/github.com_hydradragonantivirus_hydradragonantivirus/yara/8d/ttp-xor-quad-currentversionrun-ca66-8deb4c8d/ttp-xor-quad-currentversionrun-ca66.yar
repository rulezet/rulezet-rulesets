rule TTP_XOR_QUAD_CurrentVersionRun_ca66 {
  strings:
    $key_ca66 = { 99 09 [2] bd 07 [2] 96 2b [2] b8 09 [2] ac 12 [2] a3 08 [2] bd 15 [2] bf 14 [2] a4 12 [2] b8 15 [2] a4 3a }

  condition:
    any of them
}