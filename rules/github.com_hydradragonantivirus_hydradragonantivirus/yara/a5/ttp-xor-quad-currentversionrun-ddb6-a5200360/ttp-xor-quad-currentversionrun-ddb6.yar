rule TTP_XOR_QUAD_CurrentVersionRun_ddb6 {
  strings:
    $key_ddb6 = { 8e d9 [2] aa d7 [2] 81 fb [2] af d9 [2] bb c2 [2] b4 d8 [2] aa c5 [2] a8 c4 [2] b3 c2 [2] af c5 [2] b3 ea }

  condition:
    any of them
}