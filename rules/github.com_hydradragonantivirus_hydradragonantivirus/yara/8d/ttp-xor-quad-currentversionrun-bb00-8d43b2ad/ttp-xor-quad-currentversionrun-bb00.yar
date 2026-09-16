rule TTP_XOR_QUAD_CurrentVersionRun_bb00 {
  strings:
    $key_bb00 = { e8 6f [2] cc 61 [2] e7 4d [2] c9 6f [2] dd 74 [2] d2 6e [2] cc 73 [2] ce 72 [2] d5 74 [2] c9 73 [2] d5 5c }

  condition:
    any of them
}