rule TTP_XOR_QUAD_CurrentVersionRun_ddbe {
  strings:
    $key_ddbe = { 8e d1 [2] aa df [2] 81 f3 [2] af d1 [2] bb ca [2] b4 d0 [2] aa cd [2] a8 cc [2] b3 ca [2] af cd [2] b3 e2 }

  condition:
    any of them
}