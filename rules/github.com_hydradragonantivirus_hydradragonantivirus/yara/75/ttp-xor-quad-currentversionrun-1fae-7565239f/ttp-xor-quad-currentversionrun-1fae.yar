rule TTP_XOR_QUAD_CurrentVersionRun_1fae {
  strings:
    $key_1fae = { 4c c1 [2] 68 cf [2] 43 e3 [2] 6d c1 [2] 79 da [2] 76 c0 [2] 68 dd [2] 6a dc [2] 71 da [2] 6d dd [2] 71 f2 }

  condition:
    any of them
}