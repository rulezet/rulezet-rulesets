rule TTP_XOR_QUAD_CurrentVersionRun_ac45 {
  strings:
    $key_ac45 = { ff 2a [2] db 24 [2] f0 08 [2] de 2a [2] ca 31 [2] c5 2b [2] db 36 [2] d9 37 [2] c2 31 [2] de 36 [2] c2 19 }

  condition:
    any of them
}