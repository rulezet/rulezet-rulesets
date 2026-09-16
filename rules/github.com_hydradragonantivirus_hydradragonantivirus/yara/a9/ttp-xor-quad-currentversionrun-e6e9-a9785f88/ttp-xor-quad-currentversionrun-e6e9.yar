rule TTP_XOR_QUAD_CurrentVersionRun_e6e9 {
  strings:
    $key_e6e9 = { b5 86 [2] 91 88 [2] ba a4 [2] 94 86 [2] 80 9d [2] 8f 87 [2] 91 9a [2] 93 9b [2] 88 9d [2] 94 9a [2] 88 b5 }

  condition:
    any of them
}