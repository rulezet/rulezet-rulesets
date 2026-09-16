rule TTP_XOR_QUAD_CurrentVersionRun_a96f {
  strings:
    $key_a96f = { fa 00 [2] de 0e [2] f5 22 [2] db 00 [2] cf 1b [2] c0 01 [2] de 1c [2] dc 1d [2] c7 1b [2] db 1c [2] c7 33 }

  condition:
    any of them
}