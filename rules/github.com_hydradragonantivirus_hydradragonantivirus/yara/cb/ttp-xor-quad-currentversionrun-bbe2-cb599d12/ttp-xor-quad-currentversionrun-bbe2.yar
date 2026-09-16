rule TTP_XOR_QUAD_CurrentVersionRun_bbe2 {
  strings:
    $key_bbe2 = { e8 8d [2] cc 83 [2] e7 af [2] c9 8d [2] dd 96 [2] d2 8c [2] cc 91 [2] ce 90 [2] d5 96 [2] c9 91 [2] d5 be }

  condition:
    any of them
}