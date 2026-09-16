rule TTP_XOR_QUAD_CurrentVersionRun_cbb7 {
  strings:
    $key_cbb7 = { 98 d8 [2] bc d6 [2] 97 fa [2] b9 d8 [2] ad c3 [2] a2 d9 [2] bc c4 [2] be c5 [2] a5 c3 [2] b9 c4 [2] a5 eb }

  condition:
    any of them
}