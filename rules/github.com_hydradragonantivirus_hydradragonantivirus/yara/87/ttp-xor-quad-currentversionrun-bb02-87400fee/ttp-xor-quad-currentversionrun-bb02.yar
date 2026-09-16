rule TTP_XOR_QUAD_CurrentVersionRun_bb02 {
  strings:
    $key_bb02 = { e8 6d [2] cc 63 [2] e7 4f [2] c9 6d [2] dd 76 [2] d2 6c [2] cc 71 [2] ce 70 [2] d5 76 [2] c9 71 [2] d5 5e }

  condition:
    any of them
}