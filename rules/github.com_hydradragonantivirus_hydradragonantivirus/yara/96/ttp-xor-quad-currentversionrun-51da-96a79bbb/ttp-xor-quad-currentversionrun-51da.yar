rule TTP_XOR_QUAD_CurrentVersionRun_51da {
  strings:
    $key_51da = { 02 b5 [2] 26 bb [2] 0d 97 [2] 23 b5 [2] 37 ae [2] 38 b4 [2] 26 a9 [2] 24 a8 [2] 3f ae [2] 23 a9 [2] 3f 86 }

  condition:
    any of them
}