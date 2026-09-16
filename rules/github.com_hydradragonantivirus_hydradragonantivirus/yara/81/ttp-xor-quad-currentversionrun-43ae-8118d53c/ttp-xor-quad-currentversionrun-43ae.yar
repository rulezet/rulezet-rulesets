rule TTP_XOR_QUAD_CurrentVersionRun_43ae {
  strings:
    $key_43ae = { 10 c1 [2] 34 cf [2] 1f e3 [2] 31 c1 [2] 25 da [2] 2a c0 [2] 34 dd [2] 36 dc [2] 2d da [2] 31 dd [2] 2d f2 }

  condition:
    any of them
}