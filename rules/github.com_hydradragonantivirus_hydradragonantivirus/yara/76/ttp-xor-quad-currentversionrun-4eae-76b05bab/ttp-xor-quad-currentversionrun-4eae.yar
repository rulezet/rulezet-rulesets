rule TTP_XOR_QUAD_CurrentVersionRun_4eae {
  strings:
    $key_4eae = { 1d c1 [2] 39 cf [2] 12 e3 [2] 3c c1 [2] 28 da [2] 27 c0 [2] 39 dd [2] 3b dc [2] 20 da [2] 3c dd [2] 20 f2 }

  condition:
    any of them
}