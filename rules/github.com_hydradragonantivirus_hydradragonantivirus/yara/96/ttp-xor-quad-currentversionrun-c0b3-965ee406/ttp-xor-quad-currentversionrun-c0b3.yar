rule TTP_XOR_QUAD_CurrentVersionRun_c0b3 {
  strings:
    $key_c0b3 = { 93 dc [2] b7 d2 [2] 9c fe [2] b2 dc [2] a6 c7 [2] a9 dd [2] b7 c0 [2] b5 c1 [2] ae c7 [2] b2 c0 [2] ae ef }

  condition:
    any of them
}