rule TTP_XOR_QUAD_CurrentVersionRun_c4b0 {
  strings:
    $key_c4b0 = { 97 df [2] b3 d1 [2] 98 fd [2] b6 df [2] a2 c4 [2] ad de [2] b3 c3 [2] b1 c2 [2] aa c4 [2] b6 c3 [2] aa ec }

  condition:
    any of them
}