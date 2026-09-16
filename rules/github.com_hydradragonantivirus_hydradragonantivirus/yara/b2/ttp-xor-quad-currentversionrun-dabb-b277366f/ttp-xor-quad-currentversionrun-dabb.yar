rule TTP_XOR_QUAD_CurrentVersionRun_dabb {
  strings:
    $key_dabb = { 89 d4 [2] ad da [2] 86 f6 [2] a8 d4 [2] bc cf [2] b3 d5 [2] ad c8 [2] af c9 [2] b4 cf [2] a8 c8 [2] b4 e7 }

  condition:
    any of them
}