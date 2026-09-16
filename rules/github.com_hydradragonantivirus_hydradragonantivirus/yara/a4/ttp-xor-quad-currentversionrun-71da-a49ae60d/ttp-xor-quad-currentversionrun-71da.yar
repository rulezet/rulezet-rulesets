rule TTP_XOR_QUAD_CurrentVersionRun_71da {
  strings:
    $key_71da = { 22 b5 [2] 06 bb [2] 2d 97 [2] 03 b5 [2] 17 ae [2] 18 b4 [2] 06 a9 [2] 04 a8 [2] 1f ae [2] 03 a9 [2] 1f 86 }

  condition:
    any of them
}