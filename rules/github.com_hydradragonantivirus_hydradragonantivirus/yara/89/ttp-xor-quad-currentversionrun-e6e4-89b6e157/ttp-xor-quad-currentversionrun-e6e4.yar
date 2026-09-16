rule TTP_XOR_QUAD_CurrentVersionRun_e6e4 {
  strings:
    $key_e6e4 = { b5 8b [2] 91 85 [2] ba a9 [2] 94 8b [2] 80 90 [2] 8f 8a [2] 91 97 [2] 93 96 [2] 88 90 [2] 94 97 [2] 88 b8 }

  condition:
    any of them
}