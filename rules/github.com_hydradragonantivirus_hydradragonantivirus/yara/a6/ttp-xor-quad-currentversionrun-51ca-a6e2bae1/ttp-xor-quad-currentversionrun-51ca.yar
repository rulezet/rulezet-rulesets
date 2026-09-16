rule TTP_XOR_QUAD_CurrentVersionRun_51ca {
  strings:
    $key_51ca = { 02 a5 [2] 26 ab [2] 0d 87 [2] 23 a5 [2] 37 be [2] 38 a4 [2] 26 b9 [2] 24 b8 [2] 3f be [2] 23 b9 [2] 3f 96 }

  condition:
    any of them
}