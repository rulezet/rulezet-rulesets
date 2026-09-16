rule TTP_XOR_QUAD_CurrentVersionRun_d4fc {
  strings:
    $key_d4fc = { 87 93 [2] a3 9d [2] 88 b1 [2] a6 93 [2] b2 88 [2] bd 92 [2] a3 8f [2] a1 8e [2] ba 88 [2] a6 8f [2] ba a0 }

  condition:
    any of them
}