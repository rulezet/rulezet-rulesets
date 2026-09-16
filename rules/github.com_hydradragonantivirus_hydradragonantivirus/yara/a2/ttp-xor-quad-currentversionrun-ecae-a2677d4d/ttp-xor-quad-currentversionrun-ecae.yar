rule TTP_XOR_QUAD_CurrentVersionRun_ecae {
  strings:
    $key_ecae = { bf c1 [2] 9b cf [2] b0 e3 [2] 9e c1 [2] 8a da [2] 85 c0 [2] 9b dd [2] 99 dc [2] 82 da [2] 9e dd [2] 82 f2 }

  condition:
    any of them
}