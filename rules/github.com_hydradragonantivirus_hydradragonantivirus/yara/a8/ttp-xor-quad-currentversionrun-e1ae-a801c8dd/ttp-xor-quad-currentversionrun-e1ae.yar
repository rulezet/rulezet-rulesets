rule TTP_XOR_QUAD_CurrentVersionRun_e1ae {
  strings:
    $key_e1ae = { b2 c1 [2] 96 cf [2] bd e3 [2] 93 c1 [2] 87 da [2] 88 c0 [2] 96 dd [2] 94 dc [2] 8f da [2] 93 dd [2] 8f f2 }

  condition:
    any of them
}