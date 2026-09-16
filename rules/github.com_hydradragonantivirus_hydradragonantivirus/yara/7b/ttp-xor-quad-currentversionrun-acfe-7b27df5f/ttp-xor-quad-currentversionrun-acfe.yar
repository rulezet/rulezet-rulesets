rule TTP_XOR_QUAD_CurrentVersionRun_acfe {
  strings:
    $key_acfe = { ff 91 [2] db 9f [2] f0 b3 [2] de 91 [2] ca 8a [2] c5 90 [2] db 8d [2] d9 8c [2] c2 8a [2] de 8d [2] c2 a2 }

  condition:
    any of them
}