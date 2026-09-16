rule TTP_XOR_QUAD_CurrentVersionRun_e6d7 {
  strings:
    $key_e6d7 = { b5 b8 [2] 91 b6 [2] ba 9a [2] 94 b8 [2] 80 a3 [2] 8f b9 [2] 91 a4 [2] 93 a5 [2] 88 a3 [2] 94 a4 [2] 88 8b }

  condition:
    any of them
}