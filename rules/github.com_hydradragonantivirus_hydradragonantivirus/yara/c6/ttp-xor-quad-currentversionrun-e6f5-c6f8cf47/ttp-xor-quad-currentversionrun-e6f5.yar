rule TTP_XOR_QUAD_CurrentVersionRun_e6f5 {
  strings:
    $key_e6f5 = { b5 9a [2] 91 94 [2] ba b8 [2] 94 9a [2] 80 81 [2] 8f 9b [2] 91 86 [2] 93 87 [2] 88 81 [2] 94 86 [2] 88 a9 }

  condition:
    any of them
}