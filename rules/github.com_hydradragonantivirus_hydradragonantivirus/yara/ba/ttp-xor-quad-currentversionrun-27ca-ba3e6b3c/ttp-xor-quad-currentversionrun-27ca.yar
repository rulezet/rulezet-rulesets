rule TTP_XOR_QUAD_CurrentVersionRun_27ca {
  strings:
    $key_27ca = { 74 a5 [2] 50 ab [2] 7b 87 [2] 55 a5 [2] 41 be [2] 4e a4 [2] 50 b9 [2] 52 b8 [2] 49 be [2] 55 b9 [2] 49 96 }

  condition:
    any of them
}