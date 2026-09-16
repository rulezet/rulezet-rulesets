rule TTP_XOR_QUAD_CurrentVersionRun_e675 {
  strings:
    $key_e675 = { b5 1a [2] 91 14 [2] ba 38 [2] 94 1a [2] 80 01 [2] 8f 1b [2] 91 06 [2] 93 07 [2] 88 01 [2] 94 06 [2] 88 29 }

  condition:
    any of them
}