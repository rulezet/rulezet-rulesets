rule TTP_XOR_QUAD_CurrentVersionRun_e679 {
  strings:
    $key_e679 = { b5 16 [2] 91 18 [2] ba 34 [2] 94 16 [2] 80 0d [2] 8f 17 [2] 91 0a [2] 93 0b [2] 88 0d [2] 94 0a [2] 88 25 }

  condition:
    any of them
}