rule TTP_XOR_QUAD_CurrentVersionRun_cf1f {
  strings:
    $key_cf1f = { 9c 70 [2] b8 7e [2] 93 52 [2] bd 70 [2] a9 6b [2] a6 71 [2] b8 6c [2] ba 6d [2] a1 6b [2] bd 6c [2] a1 43 }

  condition:
    any of them
}