rule TTP_XOR_QUAD_CurrentVersionRun_65ae {
  strings:
    $key_65ae = { 36 c1 [2] 12 cf [2] 39 e3 [2] 17 c1 [2] 03 da [2] 0c c0 [2] 12 dd [2] 10 dc [2] 0b da [2] 17 dd [2] 0b f2 }

  condition:
    any of them
}