rule TTP_XOR_QUAD_CurrentVersionRun_cff7 {
  strings:
    $key_cff7 = { 9c 98 [2] b8 96 [2] 93 ba [2] bd 98 [2] a9 83 [2] a6 99 [2] b8 84 [2] ba 85 [2] a1 83 [2] bd 84 [2] a1 ab }

  condition:
    any of them
}