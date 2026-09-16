rule TTP_XOR_QUAD_CurrentVersionRun_c0d1 {
  strings:
    $key_c0d1 = { 93 be [2] b7 b0 [2] 9c 9c [2] b2 be [2] a6 a5 [2] a9 bf [2] b7 a2 [2] b5 a3 [2] ae a5 [2] b2 a2 [2] ae 8d }

  condition:
    any of them
}