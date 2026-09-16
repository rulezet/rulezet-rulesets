rule TTP_XOR_QUAD_CurrentVersionRun_20ca {
  strings:
    $key_20ca = { 73 a5 [2] 57 ab [2] 7c 87 [2] 52 a5 [2] 46 be [2] 49 a4 [2] 57 b9 [2] 55 b8 [2] 4e be [2] 52 b9 [2] 4e 96 }

  condition:
    any of them
}