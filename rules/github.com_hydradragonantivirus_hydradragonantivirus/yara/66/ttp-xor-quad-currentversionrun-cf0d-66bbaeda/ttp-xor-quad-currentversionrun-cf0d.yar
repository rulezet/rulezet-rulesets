rule TTP_XOR_QUAD_CurrentVersionRun_cf0d {
  strings:
    $key_cf0d = { 9c 62 [2] b8 6c [2] 93 40 [2] bd 62 [2] a9 79 [2] a6 63 [2] b8 7e [2] ba 7f [2] a1 79 [2] bd 7e [2] a1 51 }

  condition:
    any of them
}