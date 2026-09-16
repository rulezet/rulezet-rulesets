rule TTP_XOR_QUAD_CurrentVersionRun_58ae {
  strings:
    $key_58ae = { 0b c1 [2] 2f cf [2] 04 e3 [2] 2a c1 [2] 3e da [2] 31 c0 [2] 2f dd [2] 2d dc [2] 36 da [2] 2a dd [2] 36 f2 }

  condition:
    any of them
}