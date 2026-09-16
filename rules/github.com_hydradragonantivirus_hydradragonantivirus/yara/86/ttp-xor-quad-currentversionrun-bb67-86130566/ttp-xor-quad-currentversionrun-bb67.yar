rule TTP_XOR_QUAD_CurrentVersionRun_bb67 {
  strings:
    $key_bb67 = { e8 08 [2] cc 06 [2] e7 2a [2] c9 08 [2] dd 13 [2] d2 09 [2] cc 14 [2] ce 15 [2] d5 13 [2] c9 14 [2] d5 3b }

  condition:
    any of them
}