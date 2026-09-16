rule TTP_XOR_QUAD_CurrentVersionRun_00ca {
  strings:
    $key_00ca = { 53 a5 [2] 77 ab [2] 5c 87 [2] 72 a5 [2] 66 be [2] 69 a4 [2] 77 b9 [2] 75 b8 [2] 6e be [2] 72 b9 [2] 6e 96 }

  condition:
    any of them
}