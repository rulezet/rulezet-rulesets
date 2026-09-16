rule TTP_XOR_QUAD_CurrentVersionRun_e4b9 {
  strings:
    $key_e4b9 = { b7 d6 [2] 93 d8 [2] b8 f4 [2] 96 d6 [2] 82 cd [2] 8d d7 [2] 93 ca [2] 91 cb [2] 8a cd [2] 96 ca [2] 8a e5 }

  condition:
    any of them
}