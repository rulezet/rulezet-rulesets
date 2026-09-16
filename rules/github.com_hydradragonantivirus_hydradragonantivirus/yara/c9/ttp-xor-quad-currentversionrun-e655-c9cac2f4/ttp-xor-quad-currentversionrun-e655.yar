rule TTP_XOR_QUAD_CurrentVersionRun_e655 {
  strings:
    $key_e655 = { b5 3a [2] 91 34 [2] ba 18 [2] 94 3a [2] 80 21 [2] 8f 3b [2] 91 26 [2] 93 27 [2] 88 21 [2] 94 26 [2] 88 09 }

  condition:
    any of them
}