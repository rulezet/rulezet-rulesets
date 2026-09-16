rule TTP_XOR_QUAD_CurrentVersionRun_ca46 {
  strings:
    $key_ca46 = { 99 29 [2] bd 27 [2] 96 0b [2] b8 29 [2] ac 32 [2] a3 28 [2] bd 35 [2] bf 34 [2] a4 32 [2] b8 35 [2] a4 1a }

  condition:
    any of them
}