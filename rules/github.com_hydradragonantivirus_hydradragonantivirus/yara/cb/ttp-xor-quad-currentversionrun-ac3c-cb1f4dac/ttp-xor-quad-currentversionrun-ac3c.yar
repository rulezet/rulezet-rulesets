rule TTP_XOR_QUAD_CurrentVersionRun_ac3c {
  strings:
    $key_ac3c = { ff 53 [2] db 5d [2] f0 71 [2] de 53 [2] ca 48 [2] c5 52 [2] db 4f [2] d9 4e [2] c2 48 [2] de 4f [2] c2 60 }

  condition:
    any of them
}