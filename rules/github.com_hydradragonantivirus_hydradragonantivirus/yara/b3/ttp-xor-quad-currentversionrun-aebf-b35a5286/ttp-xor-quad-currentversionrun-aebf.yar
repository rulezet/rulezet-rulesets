rule TTP_XOR_QUAD_CurrentVersionRun_aebf {
  strings:
    $key_aebf = { fd d0 [2] d9 de [2] f2 f2 [2] dc d0 [2] c8 cb [2] c7 d1 [2] d9 cc [2] db cd [2] c0 cb [2] dc cc [2] c0 e3 }

  condition:
    any of them
}