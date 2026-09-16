rule TTP_XOR_QUAD_CurrentVersionRun_d42f {
  strings:
    $key_d42f = { 87 40 [2] a3 4e [2] 88 62 [2] a6 40 [2] b2 5b [2] bd 41 [2] a3 5c [2] a1 5d [2] ba 5b [2] a6 5c [2] ba 73 }

  condition:
    any of them
}