rule TTP_XOR_QUAD_CurrentVersionRun_ac01 {
  strings:
    $key_ac01 = { ff 6e [2] db 60 [2] f0 4c [2] de 6e [2] ca 75 [2] c5 6f [2] db 72 [2] d9 73 [2] c2 75 [2] de 72 [2] c2 5d }

  condition:
    any of them
}