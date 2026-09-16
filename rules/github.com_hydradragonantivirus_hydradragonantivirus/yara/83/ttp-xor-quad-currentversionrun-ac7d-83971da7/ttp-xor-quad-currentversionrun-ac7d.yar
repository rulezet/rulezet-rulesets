rule TTP_XOR_QUAD_CurrentVersionRun_ac7d {
  strings:
    $key_ac7d = { ff 12 [2] db 1c [2] f0 30 [2] de 12 [2] ca 09 [2] c5 13 [2] db 0e [2] d9 0f [2] c2 09 [2] de 0e [2] c2 21 }

  condition:
    any of them
}