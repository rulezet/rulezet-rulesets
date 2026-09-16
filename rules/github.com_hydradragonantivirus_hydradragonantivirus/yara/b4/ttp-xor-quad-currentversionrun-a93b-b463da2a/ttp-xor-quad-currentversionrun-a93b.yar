rule TTP_XOR_QUAD_CurrentVersionRun_a93b {
  strings:
    $key_a93b = { fa 54 [2] de 5a [2] f5 76 [2] db 54 [2] cf 4f [2] c0 55 [2] de 48 [2] dc 49 [2] c7 4f [2] db 48 [2] c7 67 }

  condition:
    any of them
}