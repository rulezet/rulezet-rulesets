rule TTP_XOR_QUAD_CurrentVersionRun_e608 {
  strings:
    $key_e608 = { b5 67 [2] 91 69 [2] ba 45 [2] 94 67 [2] 80 7c [2] 8f 66 [2] 91 7b [2] 93 7a [2] 88 7c [2] 94 7b [2] 88 54 }

  condition:
    any of them
}