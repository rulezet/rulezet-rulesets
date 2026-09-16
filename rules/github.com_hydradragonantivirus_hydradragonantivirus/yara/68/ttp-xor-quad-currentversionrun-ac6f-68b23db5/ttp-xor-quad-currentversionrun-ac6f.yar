rule TTP_XOR_QUAD_CurrentVersionRun_ac6f {
  strings:
    $key_ac6f = { ff 00 [2] db 0e [2] f0 22 [2] de 00 [2] ca 1b [2] c5 01 [2] db 1c [2] d9 1d [2] c2 1b [2] de 1c [2] c2 33 }

  condition:
    any of them
}