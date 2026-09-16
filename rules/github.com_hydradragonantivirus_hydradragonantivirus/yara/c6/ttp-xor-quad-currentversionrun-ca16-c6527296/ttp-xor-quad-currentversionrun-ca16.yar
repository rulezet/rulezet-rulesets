rule TTP_XOR_QUAD_CurrentVersionRun_ca16 {
  strings:
    $key_ca16 = { 99 79 [2] bd 77 [2] 96 5b [2] b8 79 [2] ac 62 [2] a3 78 [2] bd 65 [2] bf 64 [2] a4 62 [2] b8 65 [2] a4 4a }

  condition:
    any of them
}