rule TTP_XOR_QUAD_CurrentVersionRun_61da {
  strings:
    $key_61da = { 32 b5 [2] 16 bb [2] 3d 97 [2] 13 b5 [2] 07 ae [2] 08 b4 [2] 16 a9 [2] 14 a8 [2] 0f ae [2] 13 a9 [2] 0f 86 }

  condition:
    any of them
}