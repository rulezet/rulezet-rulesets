rule TTP_XOR_QUAD_CurrentVersionRun_41ca {
  strings:
    $key_41ca = { 12 a5 [2] 36 ab [2] 1d 87 [2] 33 a5 [2] 27 be [2] 28 a4 [2] 36 b9 [2] 34 b8 [2] 2f be [2] 33 b9 [2] 2f 96 }

  condition:
    any of them
}