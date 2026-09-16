rule TTP_XOR_QUAD_CurrentVersionRun_d342 {
  strings:
    $key_d342 = { 80 2d [2] a4 23 [2] 8f 0f [2] a1 2d [2] b5 36 [2] ba 2c [2] a4 31 [2] a6 30 [2] bd 36 [2] a1 31 [2] bd 1e }

  condition:
    any of them
}