rule TTP_XOR_QUAD_CurrentVersionRun_bb06 {
  strings:
    $key_bb06 = { e8 69 [2] cc 67 [2] e7 4b [2] c9 69 [2] dd 72 [2] d2 68 [2] cc 75 [2] ce 74 [2] d5 72 [2] c9 75 [2] d5 5a }

  condition:
    any of them
}