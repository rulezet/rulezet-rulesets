rule TTP_XOR_QUAD_CurrentVersionRun_05ae {
  strings:
    $key_05ae = { 56 c1 [2] 72 cf [2] 59 e3 [2] 77 c1 [2] 63 da [2] 6c c0 [2] 72 dd [2] 70 dc [2] 6b da [2] 77 dd [2] 6b f2 }

  condition:
    any of them
}