rule TTP_XOR_QUAD_CurrentVersionRun_bb01 {
  strings:
    $key_bb01 = { e8 6e [2] cc 60 [2] e7 4c [2] c9 6e [2] dd 75 [2] d2 6f [2] cc 72 [2] ce 73 [2] d5 75 [2] c9 72 [2] d5 5d }

  condition:
    any of them
}