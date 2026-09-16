rule TTP_XOR_QUAD_CurrentVersionRun_e625 {
  strings:
    $key_e625 = { b5 4a [2] 91 44 [2] ba 68 [2] 94 4a [2] 80 51 [2] 8f 4b [2] 91 56 [2] 93 57 [2] 88 51 [2] 94 56 [2] 88 79 }

  condition:
    any of them
}