rule TTP_XOR_QUAD_CurrentVersionRun_bb2c {
  strings:
    $key_bb2c = { e8 43 [2] cc 4d [2] e7 61 [2] c9 43 [2] dd 58 [2] d2 42 [2] cc 5f [2] ce 5e [2] d5 58 [2] c9 5f [2] d5 70 }

  condition:
    any of them
}