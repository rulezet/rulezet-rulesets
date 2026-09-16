rule TTP_XOR_QUAD_CurrentVersionRun_a964 {
  strings:
    $key_a964 = { fa 0b [2] de 05 [2] f5 29 [2] db 0b [2] cf 10 [2] c0 0a [2] de 17 [2] dc 16 [2] c7 10 [2] db 17 [2] c7 38 }

  condition:
    any of them
}