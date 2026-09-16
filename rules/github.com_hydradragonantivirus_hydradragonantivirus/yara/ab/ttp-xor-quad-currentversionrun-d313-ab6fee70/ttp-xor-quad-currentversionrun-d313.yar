rule TTP_XOR_QUAD_CurrentVersionRun_d313 {
  strings:
    $key_d313 = { 80 7c [2] a4 72 [2] 8f 5e [2] a1 7c [2] b5 67 [2] ba 7d [2] a4 60 [2] a6 61 [2] bd 67 [2] a1 60 [2] bd 4f }

  condition:
    any of them
}