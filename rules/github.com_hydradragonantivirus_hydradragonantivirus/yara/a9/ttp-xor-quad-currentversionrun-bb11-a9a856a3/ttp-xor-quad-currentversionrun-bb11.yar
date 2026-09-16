rule TTP_XOR_QUAD_CurrentVersionRun_bb11 {
  strings:
    $key_bb11 = { e8 7e [2] cc 70 [2] e7 5c [2] c9 7e [2] dd 65 [2] d2 7f [2] cc 62 [2] ce 63 [2] d5 65 [2] c9 62 [2] d5 4d }

  condition:
    any of them
}