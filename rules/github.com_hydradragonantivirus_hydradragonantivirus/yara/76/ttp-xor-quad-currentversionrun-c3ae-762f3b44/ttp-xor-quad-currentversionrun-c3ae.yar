rule TTP_XOR_QUAD_CurrentVersionRun_c3ae {
  strings:
    $key_c3ae = { 90 c1 [2] b4 cf [2] 9f e3 [2] b1 c1 [2] a5 da [2] aa c0 [2] b4 dd [2] b6 dc [2] ad da [2] b1 dd [2] ad f2 }

  condition:
    any of them
}