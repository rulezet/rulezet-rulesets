rule TTP_XOR_QUAD_CurrentVersionRun_c4ae {
  strings:
    $key_c4ae = { 97 c1 [2] b3 cf [2] 98 e3 [2] b6 c1 [2] a2 da [2] ad c0 [2] b3 dd [2] b1 dc [2] aa da [2] b6 dd [2] aa f2 }

  condition:
    any of them
}