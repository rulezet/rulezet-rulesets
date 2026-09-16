rule TTP_XOR_QUAD_CurrentVersionRun_d8b3 {
  strings:
    $key_d8b3 = { 8b dc [2] af d2 [2] 84 fe [2] aa dc [2] be c7 [2] b1 dd [2] af c0 [2] ad c1 [2] b6 c7 [2] aa c0 [2] b6 ef }

  condition:
    any of them
}