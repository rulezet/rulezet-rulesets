rule TTP_XOR_QUAD_CurrentVersionRun_11ae {
  strings:
    $key_11ae = { 42 c1 [2] 66 cf [2] 4d e3 [2] 63 c1 [2] 77 da [2] 78 c0 [2] 66 dd [2] 64 dc [2] 7f da [2] 63 dd [2] 7f f2 }

  condition:
    any of them
}