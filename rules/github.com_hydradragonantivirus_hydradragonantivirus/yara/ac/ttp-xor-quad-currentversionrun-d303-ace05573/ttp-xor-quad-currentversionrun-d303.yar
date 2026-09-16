rule TTP_XOR_QUAD_CurrentVersionRun_d303 {
  strings:
    $key_d303 = { 80 6c [2] a4 62 [2] 8f 4e [2] a1 6c [2] b5 77 [2] ba 6d [2] a4 70 [2] a6 71 [2] bd 77 [2] a1 70 [2] bd 5f }

  condition:
    any of them
}