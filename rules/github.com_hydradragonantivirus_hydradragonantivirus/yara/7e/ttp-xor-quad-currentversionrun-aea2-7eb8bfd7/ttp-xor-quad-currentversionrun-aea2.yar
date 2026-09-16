rule TTP_XOR_QUAD_CurrentVersionRun_aea2 {
  strings:
    $key_aea2 = { fd cd [2] d9 c3 [2] f2 ef [2] dc cd [2] c8 d6 [2] c7 cc [2] d9 d1 [2] db d0 [2] c0 d6 [2] dc d1 [2] c0 fe }

  condition:
    any of them
}