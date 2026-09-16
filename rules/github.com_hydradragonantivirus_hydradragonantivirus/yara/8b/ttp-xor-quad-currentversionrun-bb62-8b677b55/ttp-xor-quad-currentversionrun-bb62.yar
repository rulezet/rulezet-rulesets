rule TTP_XOR_QUAD_CurrentVersionRun_bb62 {
  strings:
    $key_bb62 = { e8 0d [2] cc 03 [2] e7 2f [2] c9 0d [2] dd 16 [2] d2 0c [2] cc 11 [2] ce 10 [2] d5 16 [2] c9 11 [2] d5 3e }

  condition:
    any of them
}