rule TTP_XOR_QUAD_CurrentVersionRun_efae {
  strings:
    $key_efae = { bc c1 [2] 98 cf [2] b3 e3 [2] 9d c1 [2] 89 da [2] 86 c0 [2] 98 dd [2] 9a dc [2] 81 da [2] 9d dd [2] 81 f2 }

  condition:
    any of them
}