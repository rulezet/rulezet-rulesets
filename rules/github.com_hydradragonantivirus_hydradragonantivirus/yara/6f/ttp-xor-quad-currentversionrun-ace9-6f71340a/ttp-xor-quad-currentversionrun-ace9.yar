rule TTP_XOR_QUAD_CurrentVersionRun_ace9 {
  strings:
    $key_ace9 = { ff 86 [2] db 88 [2] f0 a4 [2] de 86 [2] ca 9d [2] c5 87 [2] db 9a [2] d9 9b [2] c2 9d [2] de 9a [2] c2 b5 }

  condition:
    any of them
}