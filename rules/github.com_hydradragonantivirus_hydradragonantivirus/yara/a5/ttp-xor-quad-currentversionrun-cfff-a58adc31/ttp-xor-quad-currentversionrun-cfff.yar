rule TTP_XOR_QUAD_CurrentVersionRun_cfff {
  strings:
    $key_cfff = { 9c 90 [2] b8 9e [2] 93 b2 [2] bd 90 [2] a9 8b [2] a6 91 [2] b8 8c [2] ba 8d [2] a1 8b [2] bd 8c [2] a1 a3 }

  condition:
    any of them
}