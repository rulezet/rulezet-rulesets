rule TTP_XOR_QUAD_CurrentVersionRun_d41a {
  strings:
    $key_d41a = { 87 75 [2] a3 7b [2] 88 57 [2] a6 75 [2] b2 6e [2] bd 74 [2] a3 69 [2] a1 68 [2] ba 6e [2] a6 69 [2] ba 46 }

  condition:
    any of them
}