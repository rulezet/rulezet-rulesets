rule TTP_XOR_QUAD_CurrentVersionRun_e6e8 {
  strings:
    $key_e6e8 = { b5 87 [2] 91 89 [2] ba a5 [2] 94 87 [2] 80 9c [2] 8f 86 [2] 91 9b [2] 93 9a [2] 88 9c [2] 94 9b [2] 88 b4 }

  condition:
    any of them
}