rule TTP_XOR_QUAD_CurrentVersionRun_aee6 {
  strings:
    $key_aee6 = { fd 89 [2] d9 87 [2] f2 ab [2] dc 89 [2] c8 92 [2] c7 88 [2] d9 95 [2] db 94 [2] c0 92 [2] dc 95 [2] c0 ba }

  condition:
    any of them
}