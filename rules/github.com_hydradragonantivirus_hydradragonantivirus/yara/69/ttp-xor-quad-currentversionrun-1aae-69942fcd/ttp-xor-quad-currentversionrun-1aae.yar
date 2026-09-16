rule TTP_XOR_QUAD_CurrentVersionRun_1aae {
  strings:
    $key_1aae = { 49 c1 [2] 6d cf [2] 46 e3 [2] 68 c1 [2] 7c da [2] 73 c0 [2] 6d dd [2] 6f dc [2] 74 da [2] 68 dd [2] 74 f2 }

  condition:
    any of them
}