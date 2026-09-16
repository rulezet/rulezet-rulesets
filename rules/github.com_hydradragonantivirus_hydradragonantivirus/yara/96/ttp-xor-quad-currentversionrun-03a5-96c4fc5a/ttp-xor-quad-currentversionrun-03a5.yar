rule TTP_XOR_QUAD_CurrentVersionRun_03a5 {
  strings:
    $key_03a5 = { 50 ca [2] 74 c4 [2] 5f e8 [2] 71 ca [2] 65 d1 [2] 6a cb [2] 74 d6 [2] 76 d7 [2] 6d d1 [2] 71 d6 [2] 6d f9 }

  condition:
    any of them
}