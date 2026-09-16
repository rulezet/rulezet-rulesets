rule TTP_XOR_QUAD_CurrentVersionRun_57bc {
  strings:
    $key_57bc = { 04 d3 [2] 20 dd [2] 0b f1 [2] 25 d3 [2] 31 c8 [2] 3e d2 [2] 20 cf [2] 22 ce [2] 39 c8 [2] 25 cf [2] 39 e0 }

  condition:
    any of them
}