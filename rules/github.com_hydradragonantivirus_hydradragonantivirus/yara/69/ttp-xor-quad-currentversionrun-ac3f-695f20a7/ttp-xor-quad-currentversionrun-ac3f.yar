rule TTP_XOR_QUAD_CurrentVersionRun_ac3f {
  strings:
    $key_ac3f = { ff 50 [2] db 5e [2] f0 72 [2] de 50 [2] ca 4b [2] c5 51 [2] db 4c [2] d9 4d [2] c2 4b [2] de 4c [2] c2 63 }

  condition:
    any of them
}