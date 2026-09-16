rule TTP_XOR_QUAD_CurrentVersionRun_a90b {
  strings:
    $key_a90b = { fa 64 [2] de 6a [2] f5 46 [2] db 64 [2] cf 7f [2] c0 65 [2] de 78 [2] dc 79 [2] c7 7f [2] db 78 [2] c7 57 }

  condition:
    any of them
}