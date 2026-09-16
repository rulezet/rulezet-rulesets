rule TTP_XOR_QUAD_CurrentVersionRun_e6f4 {
  strings:
    $key_e6f4 = { b5 9b [2] 91 95 [2] ba b9 [2] 94 9b [2] 80 80 [2] 8f 9a [2] 91 87 [2] 93 86 [2] 88 80 [2] 94 87 [2] 88 a8 }

  condition:
    any of them
}