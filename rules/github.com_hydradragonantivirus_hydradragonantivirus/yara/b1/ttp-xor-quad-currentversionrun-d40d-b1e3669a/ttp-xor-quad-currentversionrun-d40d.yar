rule TTP_XOR_QUAD_CurrentVersionRun_d40d {
  strings:
    $key_d40d = { 87 62 [2] a3 6c [2] 88 40 [2] a6 62 [2] b2 79 [2] bd 63 [2] a3 7e [2] a1 7f [2] ba 79 [2] a6 7e [2] ba 51 }

  condition:
    any of them
}