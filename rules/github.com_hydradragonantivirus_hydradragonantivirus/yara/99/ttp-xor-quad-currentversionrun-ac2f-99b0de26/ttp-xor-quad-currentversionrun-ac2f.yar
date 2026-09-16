rule TTP_XOR_QUAD_CurrentVersionRun_ac2f {
  strings:
    $key_ac2f = { ff 40 [2] db 4e [2] f0 62 [2] de 40 [2] ca 5b [2] c5 41 [2] db 5c [2] d9 5d [2] c2 5b [2] de 5c [2] c2 73 }

  condition:
    any of them
}