rule TTP_XOR_QUAD_CurrentVersionRun_ae8d {
  strings:
    $key_ae8d = { fd e2 [2] d9 ec [2] f2 c0 [2] dc e2 [2] c8 f9 [2] c7 e3 [2] d9 fe [2] db ff [2] c0 f9 [2] dc fe [2] c0 d1 }

  condition:
    any of them
}