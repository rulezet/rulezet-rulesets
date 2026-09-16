rule TTP_XOR_QUAD_CurrentVersionRun_61a5 {
  strings:
    $key_61a5 = { 32 ca [2] 16 c4 [2] 3d e8 [2] 13 ca [2] 07 d1 [2] 08 cb [2] 16 d6 [2] 14 d7 [2] 0f d1 [2] 13 d6 [2] 0f f9 }

  condition:
    any of them
}