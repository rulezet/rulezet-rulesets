rule TTP_XOR_QUAD_CurrentVersionRun_4cae {
  strings:
    $key_4cae = { 1f c1 [2] 3b cf [2] 10 e3 [2] 3e c1 [2] 2a da [2] 25 c0 [2] 3b dd [2] 39 dc [2] 22 da [2] 3e dd [2] 22 f2 }

  condition:
    any of them
}