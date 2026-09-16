rule TTP_XOR_QUAD_CurrentVersionRun_ac7e {
  strings:
    $key_ac7e = { ff 11 [2] db 1f [2] f0 33 [2] de 11 [2] ca 0a [2] c5 10 [2] db 0d [2] d9 0c [2] c2 0a [2] de 0d [2] c2 22 }

  condition:
    any of them
}