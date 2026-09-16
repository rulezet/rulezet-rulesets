rule TTP_XOR_QUAD_CurrentVersionRun_e6da {
  strings:
    $key_e6da = { b5 b5 [2] 91 bb [2] ba 97 [2] 94 b5 [2] 80 ae [2] 8f b4 [2] 91 a9 [2] 93 a8 [2] 88 ae [2] 94 a9 [2] 88 86 }

  condition:
    any of them
}