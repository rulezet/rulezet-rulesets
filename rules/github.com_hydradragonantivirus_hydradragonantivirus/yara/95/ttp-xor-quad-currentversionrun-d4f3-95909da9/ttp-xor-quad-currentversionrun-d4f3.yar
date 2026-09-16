rule TTP_XOR_QUAD_CurrentVersionRun_d4f3 {
  strings:
    $key_d4f3 = { 87 9c [2] a3 92 [2] 88 be [2] a6 9c [2] b2 87 [2] bd 9d [2] a3 80 [2] a1 81 [2] ba 87 [2] a6 80 [2] ba af }

  condition:
    any of them
}