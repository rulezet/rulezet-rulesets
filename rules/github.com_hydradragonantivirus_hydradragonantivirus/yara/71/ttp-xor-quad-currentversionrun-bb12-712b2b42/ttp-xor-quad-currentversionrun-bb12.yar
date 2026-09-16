rule TTP_XOR_QUAD_CurrentVersionRun_bb12 {
  strings:
    $key_bb12 = { e8 7d [2] cc 73 [2] e7 5f [2] c9 7d [2] dd 66 [2] d2 7c [2] cc 61 [2] ce 60 [2] d5 66 [2] c9 61 [2] d5 4e }

  condition:
    any of them
}