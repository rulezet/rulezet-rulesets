rule TTP_XOR_QUAD_CurrentVersionRun_bb0c {
  strings:
    $key_bb0c = { e8 63 [2] cc 6d [2] e7 41 [2] c9 63 [2] dd 78 [2] d2 62 [2] cc 7f [2] ce 7e [2] d5 78 [2] c9 7f [2] d5 50 }

  condition:
    any of them
}