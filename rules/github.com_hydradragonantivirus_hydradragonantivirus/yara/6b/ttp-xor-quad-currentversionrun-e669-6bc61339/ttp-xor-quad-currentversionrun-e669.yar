rule TTP_XOR_QUAD_CurrentVersionRun_e669 {
  strings:
    $key_e669 = { b5 06 [2] 91 08 [2] ba 24 [2] 94 06 [2] 80 1d [2] 8f 07 [2] 91 1a [2] 93 1b [2] 88 1d [2] 94 1a [2] 88 35 }

  condition:
    any of them
}