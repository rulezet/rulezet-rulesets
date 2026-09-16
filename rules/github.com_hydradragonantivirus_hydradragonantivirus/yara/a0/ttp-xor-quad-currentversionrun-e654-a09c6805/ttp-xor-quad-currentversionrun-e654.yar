rule TTP_XOR_QUAD_CurrentVersionRun_e654 {
  strings:
    $key_e654 = { b5 3b [2] 91 35 [2] ba 19 [2] 94 3b [2] 80 20 [2] 8f 3a [2] 91 27 [2] 93 26 [2] 88 20 [2] 94 27 [2] 88 08 }

  condition:
    any of them
}