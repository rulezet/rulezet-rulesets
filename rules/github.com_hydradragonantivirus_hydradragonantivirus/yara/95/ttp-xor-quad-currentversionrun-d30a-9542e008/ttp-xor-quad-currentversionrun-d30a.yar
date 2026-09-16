rule TTP_XOR_QUAD_CurrentVersionRun_d30a {
  strings:
    $key_d30a = { 80 65 [2] a4 6b [2] 8f 47 [2] a1 65 [2] b5 7e [2] ba 64 [2] a4 79 [2] a6 78 [2] bd 7e [2] a1 79 [2] bd 56 }

  condition:
    any of them
}