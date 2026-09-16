rule TTP_XOR_QUAD_CurrentVersionRun_75ae {
  strings:
    $key_75ae = { 26 c1 [2] 02 cf [2] 29 e3 [2] 07 c1 [2] 13 da [2] 1c c0 [2] 02 dd [2] 00 dc [2] 1b da [2] 07 dd [2] 1b f2 }

  condition:
    any of them
}