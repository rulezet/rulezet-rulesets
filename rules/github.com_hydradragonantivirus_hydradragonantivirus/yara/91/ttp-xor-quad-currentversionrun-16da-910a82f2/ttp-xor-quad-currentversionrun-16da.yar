rule TTP_XOR_QUAD_CurrentVersionRun_16da {
  strings:
    $key_16da = { 45 b5 [2] 61 bb [2] 4a 97 [2] 64 b5 [2] 70 ae [2] 7f b4 [2] 61 a9 [2] 63 a8 [2] 78 ae [2] 64 a9 [2] 78 86 }

  condition:
    any of them
}