rule TTP_XOR_QUAD_CurrentVersionRun_d413 {
  strings:
    $key_d413 = { 87 7c [2] a3 72 [2] 88 5e [2] a6 7c [2] b2 67 [2] bd 7d [2] a3 60 [2] a1 61 [2] ba 67 [2] a6 60 [2] ba 4f }

  condition:
    any of them
}