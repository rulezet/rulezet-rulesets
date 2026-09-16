rule TTP_XOR_QUAD_CurrentVersionRun_cf7e {
  strings:
    $key_cf7e = { 9c 11 [2] b8 1f [2] 93 33 [2] bd 11 [2] a9 0a [2] a6 10 [2] b8 0d [2] ba 0c [2] a1 0a [2] bd 0d [2] a1 22 }

  condition:
    any of them
}