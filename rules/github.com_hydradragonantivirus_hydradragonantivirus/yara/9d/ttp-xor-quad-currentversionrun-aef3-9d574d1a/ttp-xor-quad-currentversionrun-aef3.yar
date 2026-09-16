rule TTP_XOR_QUAD_CurrentVersionRun_aef3 {
  strings:
    $key_aef3 = { fd 9c [2] d9 92 [2] f2 be [2] dc 9c [2] c8 87 [2] c7 9d [2] d9 80 [2] db 81 [2] c0 87 [2] dc 80 [2] c0 af }

  condition:
    any of them
}