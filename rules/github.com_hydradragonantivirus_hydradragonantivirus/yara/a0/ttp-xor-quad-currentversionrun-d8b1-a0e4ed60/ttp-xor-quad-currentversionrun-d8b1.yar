rule TTP_XOR_QUAD_CurrentVersionRun_d8b1 {
  strings:
    $key_d8b1 = { 8b de [2] af d0 [2] 84 fc [2] aa de [2] be c5 [2] b1 df [2] af c2 [2] ad c3 [2] b6 c5 [2] aa c2 [2] b6 ed }

  condition:
    any of them
}