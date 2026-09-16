rule TTP_XOR_QUAD_CurrentVersionRun_e3ae {
  strings:
    $key_e3ae = { b0 c1 [2] 94 cf [2] bf e3 [2] 91 c1 [2] 85 da [2] 8a c0 [2] 94 dd [2] 96 dc [2] 8d da [2] 91 dd [2] 8d f2 }

  condition:
    any of them
}