rule TTP_XOR_QUAD_CurrentVersionRun_bb60 {
  strings:
    $key_bb60 = { e8 0f [2] cc 01 [2] e7 2d [2] c9 0f [2] dd 14 [2] d2 0e [2] cc 13 [2] ce 12 [2] d5 14 [2] c9 13 [2] d5 3c }

  condition:
    any of them
}