rule TTP_XOR_QUAD_CurrentVersionRun_d40f {
  strings:
    $key_d40f = { 87 60 [2] a3 6e [2] 88 42 [2] a6 60 [2] b2 7b [2] bd 61 [2] a3 7c [2] a1 7d [2] ba 7b [2] a6 7c [2] ba 53 }

  condition:
    any of them
}