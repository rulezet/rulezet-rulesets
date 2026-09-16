rule TTP_XOR_QUAD_CurrentVersionRun_d423 {
  strings:
    $key_d423 = { 87 4c [2] a3 42 [2] 88 6e [2] a6 4c [2] b2 57 [2] bd 4d [2] a3 50 [2] a1 51 [2] ba 57 [2] a6 50 [2] ba 7f }

  condition:
    any of them
}