rule TTP_XOR_QUAD_CurrentVersionRun_e604 {
  strings:
    $key_e604 = { b5 6b [2] 91 65 [2] ba 49 [2] 94 6b [2] 80 70 [2] 8f 6a [2] 91 77 [2] 93 76 [2] 88 70 [2] 94 77 [2] 88 58 }

  condition:
    any of them
}