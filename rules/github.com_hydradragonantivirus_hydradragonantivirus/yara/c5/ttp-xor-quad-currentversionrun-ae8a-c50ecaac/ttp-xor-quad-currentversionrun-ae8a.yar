rule TTP_XOR_QUAD_CurrentVersionRun_ae8a {
  strings:
    $key_ae8a = { fd e5 [2] d9 eb [2] f2 c7 [2] dc e5 [2] c8 fe [2] c7 e4 [2] d9 f9 [2] db f8 [2] c0 fe [2] dc f9 [2] c0 d6 }

  condition:
    any of them
}