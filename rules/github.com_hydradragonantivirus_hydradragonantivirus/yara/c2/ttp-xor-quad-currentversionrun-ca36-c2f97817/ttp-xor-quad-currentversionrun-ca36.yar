rule TTP_XOR_QUAD_CurrentVersionRun_ca36 {
  strings:
    $key_ca36 = { 99 59 [2] bd 57 [2] 96 7b [2] b8 59 [2] ac 42 [2] a3 58 [2] bd 45 [2] bf 44 [2] a4 42 [2] b8 45 [2] a4 6a }

  condition:
    any of them
}