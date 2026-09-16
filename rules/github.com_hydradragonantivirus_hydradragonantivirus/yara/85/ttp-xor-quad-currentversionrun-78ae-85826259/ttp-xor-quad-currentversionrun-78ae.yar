rule TTP_XOR_QUAD_CurrentVersionRun_78ae {
  strings:
    $key_78ae = { 2b c1 [2] 0f cf [2] 24 e3 [2] 0a c1 [2] 1e da [2] 11 c0 [2] 0f dd [2] 0d dc [2] 16 da [2] 0a dd [2] 16 f2 }

  condition:
    any of them
}