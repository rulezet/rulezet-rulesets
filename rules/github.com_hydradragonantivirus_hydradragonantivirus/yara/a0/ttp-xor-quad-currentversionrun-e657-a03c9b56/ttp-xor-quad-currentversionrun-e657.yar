rule TTP_XOR_QUAD_CurrentVersionRun_e657 {
  strings:
    $key_e657 = { b5 38 [2] 91 36 [2] ba 1a [2] 94 38 [2] 80 23 [2] 8f 39 [2] 91 24 [2] 93 25 [2] 88 23 [2] 94 24 [2] 88 0b }

  condition:
    any of them
}