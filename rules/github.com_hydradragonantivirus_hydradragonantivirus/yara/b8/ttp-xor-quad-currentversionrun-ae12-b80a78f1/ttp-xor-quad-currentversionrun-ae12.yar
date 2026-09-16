rule TTP_XOR_QUAD_CurrentVersionRun_ae12 {
  strings:
    $key_ae12 = { fd 7d [2] d9 73 [2] f2 5f [2] dc 7d [2] c8 66 [2] c7 7c [2] d9 61 [2] db 60 [2] c0 66 [2] dc 61 [2] c0 4e }

  condition:
    any of them
}