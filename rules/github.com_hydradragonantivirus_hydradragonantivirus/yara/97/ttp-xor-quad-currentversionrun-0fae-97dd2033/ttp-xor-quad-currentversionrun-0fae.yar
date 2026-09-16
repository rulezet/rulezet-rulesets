rule TTP_XOR_QUAD_CurrentVersionRun_0fae {
  strings:
    $key_0fae = { 5c c1 [2] 78 cf [2] 53 e3 [2] 7d c1 [2] 69 da [2] 66 c0 [2] 78 dd [2] 7a dc [2] 61 da [2] 7d dd [2] 61 f2 }

  condition:
    any of them
}