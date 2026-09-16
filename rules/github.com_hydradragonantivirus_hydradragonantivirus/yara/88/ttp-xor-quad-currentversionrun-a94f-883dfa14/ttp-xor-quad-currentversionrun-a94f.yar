rule TTP_XOR_QUAD_CurrentVersionRun_a94f {
  strings:
    $key_a94f = { fa 20 [2] de 2e [2] f5 02 [2] db 20 [2] cf 3b [2] c0 21 [2] de 3c [2] dc 3d [2] c7 3b [2] db 3c [2] c7 13 }

  condition:
    any of them
}