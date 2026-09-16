rule TTP_XOR_QUAD_CurrentVersionRun_21bc {
  strings:
    $key_21bc = { 72 d3 [2] 56 dd [2] 7d f1 [2] 53 d3 [2] 47 c8 [2] 48 d2 [2] 56 cf [2] 54 ce [2] 4f c8 [2] 53 cf [2] 4f e0 }

  condition:
    any of them
}