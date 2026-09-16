rule TTP_XOR_QUAD_CurrentVersionRun_27bc {
  strings:
    $key_27bc = { 74 d3 [2] 50 dd [2] 7b f1 [2] 55 d3 [2] 41 c8 [2] 4e d2 [2] 50 cf [2] 52 ce [2] 49 c8 [2] 55 cf [2] 49 e0 }

  condition:
    any of them
}