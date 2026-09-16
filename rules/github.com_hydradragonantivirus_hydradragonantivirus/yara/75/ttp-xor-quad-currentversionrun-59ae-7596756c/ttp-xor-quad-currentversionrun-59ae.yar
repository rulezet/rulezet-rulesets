rule TTP_XOR_QUAD_CurrentVersionRun_59ae {
  strings:
    $key_59ae = { 0a c1 [2] 2e cf [2] 05 e3 [2] 2b c1 [2] 3f da [2] 30 c0 [2] 2e dd [2] 2c dc [2] 37 da [2] 2b dd [2] 37 f2 }

  condition:
    any of them
}