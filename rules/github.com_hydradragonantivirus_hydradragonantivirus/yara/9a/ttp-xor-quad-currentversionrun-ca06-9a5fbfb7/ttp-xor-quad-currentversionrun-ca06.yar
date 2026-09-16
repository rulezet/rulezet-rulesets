rule TTP_XOR_QUAD_CurrentVersionRun_ca06 {
  strings:
    $key_ca06 = { 99 69 [2] bd 67 [2] 96 4b [2] b8 69 [2] ac 72 [2] a3 68 [2] bd 75 [2] bf 74 [2] a4 72 [2] b8 75 [2] a4 5a }

  condition:
    any of them
}