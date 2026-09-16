rule TTP_XOR_QUAD_CurrentVersionRun_d37f {
  strings:
    $key_d37f = { 80 10 [2] a4 1e [2] 8f 32 [2] a1 10 [2] b5 0b [2] ba 11 [2] a4 0c [2] a6 0d [2] bd 0b [2] a1 0c [2] bd 23 }

  condition:
    any of them
}