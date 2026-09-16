rule TTP_XOR_QUAD_CurrentVersionRun_d8bb {
  strings:
    $key_d8bb = { 8b d4 [2] af da [2] 84 f6 [2] aa d4 [2] be cf [2] b1 d5 [2] af c8 [2] ad c9 [2] b6 cf [2] aa c8 [2] b6 e7 }

  condition:
    any of them
}