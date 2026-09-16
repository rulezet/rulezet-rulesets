rule TTP_XOR_QUAD_CurrentVersionRun_e5ae {
  strings:
    $key_e5ae = { b6 c1 [2] 92 cf [2] b9 e3 [2] 97 c1 [2] 83 da [2] 8c c0 [2] 92 dd [2] 90 dc [2] 8b da [2] 97 dd [2] 8b f2 }

  condition:
    any of them
}