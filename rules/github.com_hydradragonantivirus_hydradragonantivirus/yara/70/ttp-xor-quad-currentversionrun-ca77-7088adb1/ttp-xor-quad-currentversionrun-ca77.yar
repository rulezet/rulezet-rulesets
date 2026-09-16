rule TTP_XOR_QUAD_CurrentVersionRun_ca77 {
  strings:
    $key_ca77 = { 99 18 [2] bd 16 [2] 96 3a [2] b8 18 [2] ac 03 [2] a3 19 [2] bd 04 [2] bf 05 [2] a4 03 [2] b8 04 [2] a4 2b }

  condition:
    any of them
}