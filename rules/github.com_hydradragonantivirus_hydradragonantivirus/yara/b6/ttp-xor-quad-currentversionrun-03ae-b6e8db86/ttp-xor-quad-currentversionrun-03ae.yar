rule TTP_XOR_QUAD_CurrentVersionRun_03ae {
  strings:
    $key_03ae = { 50 c1 [2] 74 cf [2] 5f e3 [2] 71 c1 [2] 65 da [2] 6a c0 [2] 74 dd [2] 76 dc [2] 6d da [2] 71 dd [2] 6d f2 }

  condition:
    any of them
}