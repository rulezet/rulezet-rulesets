rule TTP_XOR_QUAD_CurrentVersionRun_a917 {
  strings:
    $key_a917 = { fa 78 [2] de 76 [2] f5 5a [2] db 78 [2] cf 63 [2] c0 79 [2] de 64 [2] dc 65 [2] c7 63 [2] db 64 [2] c7 4b }

  condition:
    any of them
}