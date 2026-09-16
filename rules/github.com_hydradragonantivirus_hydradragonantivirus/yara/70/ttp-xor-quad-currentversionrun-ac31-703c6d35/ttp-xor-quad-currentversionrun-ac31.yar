rule TTP_XOR_QUAD_CurrentVersionRun_ac31 {
  strings:
    $key_ac31 = { ff 5e [2] db 50 [2] f0 7c [2] de 5e [2] ca 45 [2] c5 5f [2] db 42 [2] d9 43 [2] c2 45 [2] de 42 [2] c2 6d }

  condition:
    any of them
}