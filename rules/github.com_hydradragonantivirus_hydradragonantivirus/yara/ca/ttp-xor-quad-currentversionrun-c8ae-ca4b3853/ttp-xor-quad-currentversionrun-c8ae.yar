rule TTP_XOR_QUAD_CurrentVersionRun_c8ae {
  strings:
    $key_c8ae = { 9b c1 [2] bf cf [2] 94 e3 [2] ba c1 [2] ae da [2] a1 c0 [2] bf dd [2] bd dc [2] a6 da [2] ba dd [2] a6 f2 }

  condition:
    any of them
}