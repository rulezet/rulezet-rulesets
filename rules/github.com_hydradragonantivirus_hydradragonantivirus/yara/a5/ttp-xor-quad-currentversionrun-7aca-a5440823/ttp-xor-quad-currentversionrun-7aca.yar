rule TTP_XOR_QUAD_CurrentVersionRun_7aca {
  strings:
    $key_7aca = { 29 a5 [2] 0d ab [2] 26 87 [2] 08 a5 [2] 1c be [2] 13 a4 [2] 0d b9 [2] 0f b8 [2] 14 be [2] 08 b9 [2] 14 96 }

  condition:
    any of them
}