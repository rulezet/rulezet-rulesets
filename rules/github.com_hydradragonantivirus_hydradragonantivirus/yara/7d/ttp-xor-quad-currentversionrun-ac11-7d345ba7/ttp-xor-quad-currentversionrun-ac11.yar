rule TTP_XOR_QUAD_CurrentVersionRun_ac11 {
  strings:
    $key_ac11 = { ff 7e [2] db 70 [2] f0 5c [2] de 7e [2] ca 65 [2] c5 7f [2] db 62 [2] d9 63 [2] c2 65 [2] de 62 [2] c2 4d }

  condition:
    any of them
}