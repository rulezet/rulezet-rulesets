rule TTP_XOR_QUAD_CurrentVersionRun_33ca {
  strings:
    $key_33ca = { 60 a5 [2] 44 ab [2] 6f 87 [2] 41 a5 [2] 55 be [2] 5a a4 [2] 44 b9 [2] 46 b8 [2] 5d be [2] 41 b9 [2] 5d 96 }

  condition:
    any of them
}