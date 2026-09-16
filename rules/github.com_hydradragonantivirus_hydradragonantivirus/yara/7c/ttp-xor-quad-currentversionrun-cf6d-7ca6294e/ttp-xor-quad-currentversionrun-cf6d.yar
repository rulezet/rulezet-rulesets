rule TTP_XOR_QUAD_CurrentVersionRun_cf6d {
  strings:
    $key_cf6d = { 9c 02 [2] b8 0c [2] 93 20 [2] bd 02 [2] a9 19 [2] a6 03 [2] b8 1e [2] ba 1f [2] a1 19 [2] bd 1e [2] a1 31 }

  condition:
    any of them
}