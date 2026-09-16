rule TTP_XOR_QUAD_CurrentVersionRun_acfc {
  strings:
    $key_acfc = { ff 93 [2] db 9d [2] f0 b1 [2] de 93 [2] ca 88 [2] c5 92 [2] db 8f [2] d9 8e [2] c2 88 [2] de 8f [2] c2 a0 }

  condition:
    any of them
}