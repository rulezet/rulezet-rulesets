rule TTP_XOR_QUAD_CurrentVersionRun_d8af {
  strings:
    $key_d8af = { 8b c0 [2] af ce [2] 84 e2 [2] aa c0 [2] be db [2] b1 c1 [2] af dc [2] ad dd [2] b6 db [2] aa dc [2] b6 f3 }

  condition:
    any of them
}