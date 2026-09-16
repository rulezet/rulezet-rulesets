rule TTP_XOR_QUAD_CurrentVersionRun_d4f7 {
  strings:
    $key_d4f7 = { 87 98 [2] a3 96 [2] 88 ba [2] a6 98 [2] b2 83 [2] bd 99 [2] a3 84 [2] a1 85 [2] ba 83 [2] a6 84 [2] ba ab }

  condition:
    any of them
}