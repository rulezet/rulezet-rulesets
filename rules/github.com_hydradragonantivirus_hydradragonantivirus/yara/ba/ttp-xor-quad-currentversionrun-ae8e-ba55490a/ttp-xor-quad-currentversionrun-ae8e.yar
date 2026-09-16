rule TTP_XOR_QUAD_CurrentVersionRun_ae8e {
  strings:
    $key_ae8e = { fd e1 [2] d9 ef [2] f2 c3 [2] dc e1 [2] c8 fa [2] c7 e0 [2] d9 fd [2] db fc [2] c0 fa [2] dc fd [2] c0 d2 }

  condition:
    any of them
}