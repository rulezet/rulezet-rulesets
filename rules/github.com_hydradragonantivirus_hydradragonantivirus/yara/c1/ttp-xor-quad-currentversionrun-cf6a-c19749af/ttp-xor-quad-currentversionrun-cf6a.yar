rule TTP_XOR_QUAD_CurrentVersionRun_cf6a {
  strings:
    $key_cf6a = { 9c 05 [2] b8 0b [2] 93 27 [2] bd 05 [2] a9 1e [2] a6 04 [2] b8 19 [2] ba 18 [2] a1 1e [2] bd 19 [2] a1 36 }

  condition:
    any of them
}