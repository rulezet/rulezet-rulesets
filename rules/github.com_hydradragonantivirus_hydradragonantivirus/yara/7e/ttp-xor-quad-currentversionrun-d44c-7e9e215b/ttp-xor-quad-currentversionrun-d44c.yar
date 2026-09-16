rule TTP_XOR_QUAD_CurrentVersionRun_d44c {
  strings:
    $key_d44c = { 87 23 [2] a3 2d [2] 88 01 [2] a6 23 [2] b2 38 [2] bd 22 [2] a3 3f [2] a1 3e [2] ba 38 [2] a6 3f [2] ba 10 }

  condition:
    any of them
}