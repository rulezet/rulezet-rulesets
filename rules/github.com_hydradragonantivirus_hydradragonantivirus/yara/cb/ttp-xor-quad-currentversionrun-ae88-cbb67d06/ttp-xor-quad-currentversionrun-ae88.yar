rule TTP_XOR_QUAD_CurrentVersionRun_ae88 {
  strings:
    $key_ae88 = { fd e7 [2] d9 e9 [2] f2 c5 [2] dc e7 [2] c8 fc [2] c7 e6 [2] d9 fb [2] db fa [2] c0 fc [2] dc fb [2] c0 d4 }

  condition:
    any of them
}