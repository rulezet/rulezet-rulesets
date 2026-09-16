rule TTP_XOR_QUAD_CurrentVersionRun_ac10 {
  strings:
    $key_ac10 = { ff 7f [2] db 71 [2] f0 5d [2] de 7f [2] ca 64 [2] c5 7e [2] db 63 [2] d9 62 [2] c2 64 [2] de 63 [2] c2 4c }

  condition:
    any of them
}