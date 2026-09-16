rule TTP_XOR_QUAD_CurrentVersionRun_54da {
  strings:
    $key_54da = { 07 b5 [2] 23 bb [2] 08 97 [2] 26 b5 [2] 32 ae [2] 3d b4 [2] 23 a9 [2] 21 a8 [2] 3a ae [2] 26 a9 [2] 3a 86 }

  condition:
    any of them
}