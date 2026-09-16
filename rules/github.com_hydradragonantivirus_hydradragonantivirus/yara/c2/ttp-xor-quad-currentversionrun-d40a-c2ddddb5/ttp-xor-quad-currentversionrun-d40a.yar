rule TTP_XOR_QUAD_CurrentVersionRun_d40a {
  strings:
    $key_d40a = { 87 65 [2] a3 6b [2] 88 47 [2] a6 65 [2] b2 7e [2] bd 64 [2] a3 79 [2] a1 78 [2] ba 7e [2] a6 79 [2] ba 56 }

  condition:
    any of them
}