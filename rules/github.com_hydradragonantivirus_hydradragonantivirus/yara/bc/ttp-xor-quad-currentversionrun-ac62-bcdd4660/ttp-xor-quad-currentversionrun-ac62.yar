rule TTP_XOR_QUAD_CurrentVersionRun_ac62 {
  strings:
    $key_ac62 = { ff 0d [2] db 03 [2] f0 2f [2] de 0d [2] ca 16 [2] c5 0c [2] db 11 [2] d9 10 [2] c2 16 [2] de 11 [2] c2 3e }

  condition:
    any of them
}