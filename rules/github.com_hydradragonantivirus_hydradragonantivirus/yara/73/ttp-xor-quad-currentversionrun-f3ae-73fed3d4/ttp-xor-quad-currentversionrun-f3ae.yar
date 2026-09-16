rule TTP_XOR_QUAD_CurrentVersionRun_f3ae {
  strings:
    $key_f3ae = { a0 c1 [2] 84 cf [2] af e3 [2] 81 c1 [2] 95 da [2] 9a c0 [2] 84 dd [2] 86 dc [2] 9d da [2] 81 dd [2] 9d f2 }

  condition:
    any of them
}