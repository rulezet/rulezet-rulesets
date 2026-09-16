rule TTP_XOR_QUAD_CurrentVersionRun_c4b6 {
  strings:
    $key_c4b6 = { 97 d9 [2] b3 d7 [2] 98 fb [2] b6 d9 [2] a2 c2 [2] ad d8 [2] b3 c5 [2] b1 c4 [2] aa c2 [2] b6 c5 [2] aa ea }

  condition:
    any of them
}