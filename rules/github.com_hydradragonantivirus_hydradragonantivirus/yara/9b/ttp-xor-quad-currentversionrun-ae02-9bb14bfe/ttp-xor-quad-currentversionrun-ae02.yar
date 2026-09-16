rule TTP_XOR_QUAD_CurrentVersionRun_ae02 {
  strings:
    $key_ae02 = { fd 6d [2] d9 63 [2] f2 4f [2] dc 6d [2] c8 76 [2] c7 6c [2] d9 71 [2] db 70 [2] c0 76 [2] dc 71 [2] c0 5e }

  condition:
    any of them
}