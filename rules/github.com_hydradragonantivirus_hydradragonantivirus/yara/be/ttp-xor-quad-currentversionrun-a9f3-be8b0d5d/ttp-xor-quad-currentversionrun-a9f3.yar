rule TTP_XOR_QUAD_CurrentVersionRun_a9f3 {
  strings:
    $key_a9f3 = { fa 9c [2] de 92 [2] f5 be [2] db 9c [2] cf 87 [2] c0 9d [2] de 80 [2] dc 81 [2] c7 87 [2] db 80 [2] c7 af }

  condition:
    any of them
}