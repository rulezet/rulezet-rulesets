rule TTP_XOR_QUAD_CurrentVersionRun_cf2f {
  strings:
    $key_cf2f = { 9c 40 [2] b8 4e [2] 93 62 [2] bd 40 [2] a9 5b [2] a6 41 [2] b8 5c [2] ba 5d [2] a1 5b [2] bd 5c [2] a1 73 }

  condition:
    any of them
}