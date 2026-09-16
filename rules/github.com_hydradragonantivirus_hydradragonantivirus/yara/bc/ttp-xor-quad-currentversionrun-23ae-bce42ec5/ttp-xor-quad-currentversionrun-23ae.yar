rule TTP_XOR_QUAD_CurrentVersionRun_23ae {
  strings:
    $key_23ae = { 70 c1 [2] 54 cf [2] 7f e3 [2] 51 c1 [2] 45 da [2] 4a c0 [2] 54 dd [2] 56 dc [2] 4d da [2] 51 dd [2] 4d f2 }

  condition:
    any of them
}