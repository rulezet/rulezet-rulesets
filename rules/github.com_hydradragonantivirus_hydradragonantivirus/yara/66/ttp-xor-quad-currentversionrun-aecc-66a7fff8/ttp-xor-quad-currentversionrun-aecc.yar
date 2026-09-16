rule TTP_XOR_QUAD_CurrentVersionRun_aecc {
  strings:
    $key_aecc = { fd a3 [2] d9 ad [2] f2 81 [2] dc a3 [2] c8 b8 [2] c7 a2 [2] d9 bf [2] db be [2] c0 b8 [2] dc bf [2] c0 90 }

  condition:
    any of them
}