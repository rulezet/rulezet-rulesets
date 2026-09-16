rule TTP_XOR_QUAD_CurrentVersionRun_08ae {
  strings:
    $key_08ae = { 5b c1 [2] 7f cf [2] 54 e3 [2] 7a c1 [2] 6e da [2] 61 c0 [2] 7f dd [2] 7d dc [2] 66 da [2] 7a dd [2] 66 f2 }

  condition:
    any of them
}