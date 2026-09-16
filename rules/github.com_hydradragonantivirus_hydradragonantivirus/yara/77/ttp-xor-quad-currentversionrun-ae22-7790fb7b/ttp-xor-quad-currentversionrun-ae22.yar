rule TTP_XOR_QUAD_CurrentVersionRun_ae22 {
  strings:
    $key_ae22 = { fd 4d [2] d9 43 [2] f2 6f [2] dc 4d [2] c8 56 [2] c7 4c [2] d9 51 [2] db 50 [2] c0 56 [2] dc 51 [2] c0 7e }

  condition:
    any of them
}