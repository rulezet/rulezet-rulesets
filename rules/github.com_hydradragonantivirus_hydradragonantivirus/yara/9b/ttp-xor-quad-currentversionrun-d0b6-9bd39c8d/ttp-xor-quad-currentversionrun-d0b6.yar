rule TTP_XOR_QUAD_CurrentVersionRun_d0b6 {
  strings:
    $key_d0b6 = { 83 d9 [2] a7 d7 [2] 8c fb [2] a2 d9 [2] b6 c2 [2] b9 d8 [2] a7 c5 [2] a5 c4 [2] be c2 [2] a2 c5 [2] be ea }

  condition:
    any of them
}