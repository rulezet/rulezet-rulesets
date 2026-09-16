rule TTP_XOR_QUAD_CurrentVersionRun_35a5 {
  strings:
    $key_35a5 = { 66 ca [2] 42 c4 [2] 69 e8 [2] 47 ca [2] 53 d1 [2] 5c cb [2] 42 d6 [2] 40 d7 [2] 5b d1 [2] 47 d6 [2] 5b f9 }

  condition:
    any of them
}