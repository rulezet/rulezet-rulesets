rule TTP_XOR_QUAD_CurrentVersionRun_c0b6 {
  strings:
    $key_c0b6 = { 93 d9 [2] b7 d7 [2] 9c fb [2] b2 d9 [2] a6 c2 [2] a9 d8 [2] b7 c5 [2] b5 c4 [2] ae c2 [2] b2 c5 [2] ae ea }

  condition:
    any of them
}