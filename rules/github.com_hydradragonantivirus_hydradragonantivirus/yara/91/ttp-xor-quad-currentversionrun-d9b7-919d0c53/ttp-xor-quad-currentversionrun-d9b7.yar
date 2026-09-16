rule TTP_XOR_QUAD_CurrentVersionRun_d9b7 {
  strings:
    $key_d9b7 = { 8a d8 [2] ae d6 [2] 85 fa [2] ab d8 [2] bf c3 [2] b0 d9 [2] ae c4 [2] ac c5 [2] b7 c3 [2] ab c4 [2] b7 eb }

  condition:
    any of them
}