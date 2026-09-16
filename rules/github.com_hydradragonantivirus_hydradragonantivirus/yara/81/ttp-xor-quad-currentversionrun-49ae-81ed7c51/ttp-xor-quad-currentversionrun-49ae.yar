rule TTP_XOR_QUAD_CurrentVersionRun_49ae {
  strings:
    $key_49ae = { 1a c1 [2] 3e cf [2] 15 e3 [2] 3b c1 [2] 2f da [2] 20 c0 [2] 3e dd [2] 3c dc [2] 27 da [2] 3b dd [2] 27 f2 }

  condition:
    any of them
}