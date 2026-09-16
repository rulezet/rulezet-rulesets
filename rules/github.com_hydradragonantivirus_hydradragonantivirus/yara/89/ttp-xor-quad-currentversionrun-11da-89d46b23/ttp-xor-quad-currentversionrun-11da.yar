rule TTP_XOR_QUAD_CurrentVersionRun_11da {
  strings:
    $key_11da = { 42 b5 [2] 66 bb [2] 4d 97 [2] 63 b5 [2] 77 ae [2] 78 b4 [2] 66 a9 [2] 64 a8 [2] 7f ae [2] 63 a9 [2] 7f 86 }

  condition:
    any of them
}