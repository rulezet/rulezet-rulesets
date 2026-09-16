rule TTP_XOR_QUAD_CurrentVersionRun_12ae {
  strings:
    $key_12ae = { 41 c1 [2] 65 cf [2] 4e e3 [2] 60 c1 [2] 74 da [2] 7b c0 [2] 65 dd [2] 67 dc [2] 7c da [2] 60 dd [2] 7c f2 }

  condition:
    any of them
}