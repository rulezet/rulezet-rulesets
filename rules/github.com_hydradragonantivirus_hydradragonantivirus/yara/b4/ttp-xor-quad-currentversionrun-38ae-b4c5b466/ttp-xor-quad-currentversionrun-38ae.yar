rule TTP_XOR_QUAD_CurrentVersionRun_38ae {
  strings:
    $key_38ae = { 6b c1 [2] 4f cf [2] 64 e3 [2] 4a c1 [2] 5e da [2] 51 c0 [2] 4f dd [2] 4d dc [2] 56 da [2] 4a dd [2] 56 f2 }

  condition:
    any of them
}