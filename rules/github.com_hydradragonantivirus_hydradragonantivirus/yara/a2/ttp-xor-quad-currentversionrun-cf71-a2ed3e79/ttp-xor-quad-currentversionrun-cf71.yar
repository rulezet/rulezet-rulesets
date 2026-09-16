rule TTP_XOR_QUAD_CurrentVersionRun_cf71 {
  strings:
    $key_cf71 = { 9c 1e [2] b8 10 [2] 93 3c [2] bd 1e [2] a9 05 [2] a6 1f [2] b8 02 [2] ba 03 [2] a1 05 [2] bd 02 [2] a1 2d }

  condition:
    any of them
}