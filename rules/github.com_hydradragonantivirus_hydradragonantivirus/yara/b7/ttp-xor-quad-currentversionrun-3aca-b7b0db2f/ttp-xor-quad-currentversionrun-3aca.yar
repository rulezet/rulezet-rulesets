rule TTP_XOR_QUAD_CurrentVersionRun_3aca {
  strings:
    $key_3aca = { 69 a5 [2] 4d ab [2] 66 87 [2] 48 a5 [2] 5c be [2] 53 a4 [2] 4d b9 [2] 4f b8 [2] 54 be [2] 48 b9 [2] 54 96 }

  condition:
    any of them
}