rule TTP_XOR_QUAD_CurrentVersionRun_14ae {
  strings:
    $key_14ae = { 47 c1 [2] 63 cf [2] 48 e3 [2] 66 c1 [2] 72 da [2] 7d c0 [2] 63 dd [2] 61 dc [2] 7a da [2] 66 dd [2] 7a f2 }

  condition:
    any of them
}