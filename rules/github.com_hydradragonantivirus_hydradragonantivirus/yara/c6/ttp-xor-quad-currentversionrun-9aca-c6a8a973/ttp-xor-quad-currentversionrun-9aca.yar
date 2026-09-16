rule TTP_XOR_QUAD_CurrentVersionRun_9aca {
  strings:
    $key_9aca = { c9 a5 [2] ed ab [2] c6 87 [2] e8 a5 [2] fc be [2] f3 a4 [2] ed b9 [2] ef b8 [2] f4 be [2] e8 b9 [2] f4 96 }

  condition:
    any of them
}