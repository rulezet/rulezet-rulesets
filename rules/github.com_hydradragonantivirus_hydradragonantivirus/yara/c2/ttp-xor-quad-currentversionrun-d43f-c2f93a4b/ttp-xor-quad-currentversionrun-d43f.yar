rule TTP_XOR_QUAD_CurrentVersionRun_d43f {
  strings:
    $key_d43f = { 87 50 [2] a3 5e [2] 88 72 [2] a6 50 [2] b2 4b [2] bd 51 [2] a3 4c [2] a1 4d [2] ba 4b [2] a6 4c [2] ba 63 }

  condition:
    any of them
}