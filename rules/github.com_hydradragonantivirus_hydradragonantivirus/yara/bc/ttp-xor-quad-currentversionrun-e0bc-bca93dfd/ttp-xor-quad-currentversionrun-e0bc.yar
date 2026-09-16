rule TTP_XOR_QUAD_CurrentVersionRun_e0bc {
  strings:
    $key_e0bc = { b3 d3 [2] 97 dd [2] bc f1 [2] 92 d3 [2] 86 c8 [2] 89 d2 [2] 97 cf [2] 95 ce [2] 8e c8 [2] 92 cf [2] 8e e0 }

  condition:
    any of them
}