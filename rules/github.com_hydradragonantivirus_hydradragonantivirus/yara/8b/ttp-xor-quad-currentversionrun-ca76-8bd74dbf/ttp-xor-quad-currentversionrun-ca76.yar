rule TTP_XOR_QUAD_CurrentVersionRun_ca76 {
  strings:
    $key_ca76 = { 99 19 [2] bd 17 [2] 96 3b [2] b8 19 [2] ac 02 [2] a3 18 [2] bd 05 [2] bf 04 [2] a4 02 [2] b8 05 [2] a4 2a }

  condition:
    any of them
}