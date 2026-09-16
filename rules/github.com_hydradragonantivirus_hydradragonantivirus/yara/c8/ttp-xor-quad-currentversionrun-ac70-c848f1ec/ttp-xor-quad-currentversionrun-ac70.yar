rule TTP_XOR_QUAD_CurrentVersionRun_ac70 {
  strings:
    $key_ac70 = { ff 1f [2] db 11 [2] f0 3d [2] de 1f [2] ca 04 [2] c5 1e [2] db 03 [2] d9 02 [2] c2 04 [2] de 03 [2] c2 2c }

  condition:
    any of them
}