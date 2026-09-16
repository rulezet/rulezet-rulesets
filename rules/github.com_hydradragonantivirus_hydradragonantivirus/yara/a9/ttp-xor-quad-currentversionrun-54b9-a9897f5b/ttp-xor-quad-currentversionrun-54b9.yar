rule TTP_XOR_QUAD_CurrentVersionRun_54b9 {
  strings:
    $key_54b9 = { 07 d6 [2] 23 d8 [2] 08 f4 [2] 26 d6 [2] 32 cd [2] 3d d7 [2] 23 ca [2] 21 cb [2] 3a cd [2] 26 ca [2] 3a e5 }

  condition:
    any of them
}