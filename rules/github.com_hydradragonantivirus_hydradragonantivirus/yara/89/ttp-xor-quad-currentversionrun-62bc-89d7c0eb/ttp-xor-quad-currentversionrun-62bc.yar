rule TTP_XOR_QUAD_CurrentVersionRun_62bc {
  strings:
    $key_62bc = { 31 d3 [2] 15 dd [2] 3e f1 [2] 10 d3 [2] 04 c8 [2] 0b d2 [2] 15 cf [2] 17 ce [2] 0c c8 [2] 10 cf [2] 0c e0 }

  condition:
    any of them
}