rule TTP_XOR_QUAD_CurrentVersionRun_62ca {
  strings:
    $key_62ca = { 31 a5 [2] 15 ab [2] 3e 87 [2] 10 a5 [2] 04 be [2] 0b a4 [2] 15 b9 [2] 17 b8 [2] 0c be [2] 10 b9 [2] 0c 96 }

  condition:
    any of them
}