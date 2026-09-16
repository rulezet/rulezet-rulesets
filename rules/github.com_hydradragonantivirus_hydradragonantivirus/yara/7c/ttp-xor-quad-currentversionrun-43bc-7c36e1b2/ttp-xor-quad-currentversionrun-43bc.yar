rule TTP_XOR_QUAD_CurrentVersionRun_43bc {
  strings:
    $key_43bc = { 10 d3 [2] 34 dd [2] 1f f1 [2] 31 d3 [2] 25 c8 [2] 2a d2 [2] 34 cf [2] 36 ce [2] 2d c8 [2] 31 cf [2] 2d e0 }

  condition:
    any of them
}