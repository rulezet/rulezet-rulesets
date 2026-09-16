rule TTP_XOR_QUAD_CurrentVersionRun_aed0 {
  strings:
    $key_aed0 = { fd bf [2] d9 b1 [2] f2 9d [2] dc bf [2] c8 a4 [2] c7 be [2] d9 a3 [2] db a2 [2] c0 a4 [2] dc a3 [2] c0 8c }

  condition:
    any of them
}