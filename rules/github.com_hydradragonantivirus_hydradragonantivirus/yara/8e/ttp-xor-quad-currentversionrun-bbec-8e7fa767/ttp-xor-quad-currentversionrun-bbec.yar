rule TTP_XOR_QUAD_CurrentVersionRun_bbec {
  strings:
    $key_bbec = { e8 83 [2] cc 8d [2] e7 a1 [2] c9 83 [2] dd 98 [2] d2 82 [2] cc 9f [2] ce 9e [2] d5 98 [2] c9 9f [2] d5 b0 }

  condition:
    any of them
}