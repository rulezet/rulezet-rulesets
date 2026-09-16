rule TTP_XOR_QUAD_CurrentVersionRun_a904 {
  strings:
    $key_a904 = { fa 6b [2] de 65 [2] f5 49 [2] db 6b [2] cf 70 [2] c0 6a [2] de 77 [2] dc 76 [2] c7 70 [2] db 77 [2] c7 58 }

  condition:
    any of them
}