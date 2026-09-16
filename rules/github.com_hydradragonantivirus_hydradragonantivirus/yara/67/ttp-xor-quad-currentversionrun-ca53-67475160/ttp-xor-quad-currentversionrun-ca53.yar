rule TTP_XOR_QUAD_CurrentVersionRun_ca53 {
  strings:
    $key_ca53 = { 99 3c [2] bd 32 [2] 96 1e [2] b8 3c [2] ac 27 [2] a3 3d [2] bd 20 [2] bf 21 [2] a4 27 [2] b8 20 [2] a4 0f }

  condition:
    any of them
}