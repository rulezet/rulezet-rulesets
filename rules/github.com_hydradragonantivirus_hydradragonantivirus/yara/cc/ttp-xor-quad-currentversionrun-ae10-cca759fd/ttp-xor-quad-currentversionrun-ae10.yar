rule TTP_XOR_QUAD_CurrentVersionRun_ae10 {
  strings:
    $key_ae10 = { fd 7f [2] d9 71 [2] f2 5d [2] dc 7f [2] c8 64 [2] c7 7e [2] d9 63 [2] db 62 [2] c0 64 [2] dc 63 [2] c0 4c }

  condition:
    any of them
}