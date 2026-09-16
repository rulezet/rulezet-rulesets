rule TTP_XOR_QUAD_CurrentVersionRun_52ae {
  strings:
    $key_52ae = { 01 c1 [2] 25 cf [2] 0e e3 [2] 20 c1 [2] 34 da [2] 3b c0 [2] 25 dd [2] 27 dc [2] 3c da [2] 20 dd [2] 3c f2 }

  condition:
    any of them
}