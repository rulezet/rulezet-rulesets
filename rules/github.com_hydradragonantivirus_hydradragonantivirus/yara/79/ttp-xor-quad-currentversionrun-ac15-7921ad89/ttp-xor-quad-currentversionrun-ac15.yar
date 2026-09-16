rule TTP_XOR_QUAD_CurrentVersionRun_ac15 {
  strings:
    $key_ac15 = { ff 7a [2] db 74 [2] f0 58 [2] de 7a [2] ca 61 [2] c5 7b [2] db 66 [2] d9 67 [2] c2 61 [2] de 66 [2] c2 49 }

  condition:
    any of them
}