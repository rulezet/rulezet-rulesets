rule TTP_XOR_QUAD_CurrentVersionRun_35ae {
  strings:
    $key_35ae = { 66 c1 [2] 42 cf [2] 69 e3 [2] 47 c1 [2] 53 da [2] 5c c0 [2] 42 dd [2] 40 dc [2] 5b da [2] 47 dd [2] 5b f2 }

  condition:
    any of them
}