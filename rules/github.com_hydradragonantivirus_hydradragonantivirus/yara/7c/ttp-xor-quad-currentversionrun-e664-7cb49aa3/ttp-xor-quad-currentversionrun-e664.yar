rule TTP_XOR_QUAD_CurrentVersionRun_e664 {
  strings:
    $key_e664 = { b5 0b [2] 91 05 [2] ba 29 [2] 94 0b [2] 80 10 [2] 8f 0a [2] 91 17 [2] 93 16 [2] 88 10 [2] 94 17 [2] 88 38 }

  condition:
    any of them
}