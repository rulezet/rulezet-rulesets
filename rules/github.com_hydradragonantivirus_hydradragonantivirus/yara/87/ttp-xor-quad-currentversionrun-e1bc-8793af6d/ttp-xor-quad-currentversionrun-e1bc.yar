rule TTP_XOR_QUAD_CurrentVersionRun_e1bc {
  strings:
    $key_e1bc = { b2 d3 [2] 96 dd [2] bd f1 [2] 93 d3 [2] 87 c8 [2] 88 d2 [2] 96 cf [2] 94 ce [2] 8f c8 [2] 93 cf [2] 8f e0 }

  condition:
    any of them
}