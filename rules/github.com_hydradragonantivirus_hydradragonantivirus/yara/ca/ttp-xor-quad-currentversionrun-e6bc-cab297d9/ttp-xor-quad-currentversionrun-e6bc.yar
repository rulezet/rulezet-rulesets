rule TTP_XOR_QUAD_CurrentVersionRun_e6bc {
  strings:
    $key_e6bc = { b5 d3 [2] 91 dd [2] ba f1 [2] 94 d3 [2] 80 c8 [2] 8f d2 [2] 91 cf [2] 93 ce [2] 88 c8 [2] 94 cf [2] 88 e0 }

  condition:
    any of them
}