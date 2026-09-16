rule TTP_XOR_QUAD_CurrentVersionRun_ae31 {
  strings:
    $key_ae31 = { fd 5e [2] d9 50 [2] f2 7c [2] dc 5e [2] c8 45 [2] c7 5f [2] d9 42 [2] db 43 [2] c0 45 [2] dc 42 [2] c0 6d }

  condition:
    any of them
}