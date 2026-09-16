rule TTP_XOR_QUAD_CurrentVersionRun_dab9 {
  strings:
    $key_dab9 = { 89 d6 [2] ad d8 [2] 86 f4 [2] a8 d6 [2] bc cd [2] b3 d7 [2] ad ca [2] af cb [2] b4 cd [2] a8 ca [2] b4 e5 }

  condition:
    any of them
}