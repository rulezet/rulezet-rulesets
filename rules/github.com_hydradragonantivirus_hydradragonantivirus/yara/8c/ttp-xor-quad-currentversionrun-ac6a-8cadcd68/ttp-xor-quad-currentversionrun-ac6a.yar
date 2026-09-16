rule TTP_XOR_QUAD_CurrentVersionRun_ac6a {
  strings:
    $key_ac6a = { ff 05 [2] db 0b [2] f0 27 [2] de 05 [2] ca 1e [2] c5 04 [2] db 19 [2] d9 18 [2] c2 1e [2] de 19 [2] c2 36 }

  condition:
    any of them
}