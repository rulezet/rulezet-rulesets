rule TTP_XOR_QUAD_CurrentVersionRun_cf0a {
  strings:
    $key_cf0a = { 9c 65 [2] b8 6b [2] 93 47 [2] bd 65 [2] a9 7e [2] a6 64 [2] b8 79 [2] ba 78 [2] a1 7e [2] bd 79 [2] a1 56 }

  condition:
    any of them
}