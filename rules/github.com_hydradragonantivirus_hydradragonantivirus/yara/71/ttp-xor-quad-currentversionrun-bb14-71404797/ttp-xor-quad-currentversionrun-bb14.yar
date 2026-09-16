rule TTP_XOR_QUAD_CurrentVersionRun_bb14 {
  strings:
    $key_bb14 = { e8 7b [2] cc 75 [2] e7 59 [2] c9 7b [2] dd 60 [2] d2 7a [2] cc 67 [2] ce 66 [2] d5 60 [2] c9 67 [2] d5 48 }

  condition:
    any of them
}