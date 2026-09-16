rule TTP_XOR_QUAD_CurrentVersionRun_3cae {
  strings:
    $key_3cae = { 6f c1 [2] 4b cf [2] 60 e3 [2] 4e c1 [2] 5a da [2] 55 c0 [2] 4b dd [2] 49 dc [2] 52 da [2] 4e dd [2] 52 f2 }

  condition:
    any of them
}