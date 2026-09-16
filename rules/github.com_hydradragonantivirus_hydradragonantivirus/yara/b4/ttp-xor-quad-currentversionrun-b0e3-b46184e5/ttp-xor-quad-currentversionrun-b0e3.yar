rule TTP_XOR_QUAD_CurrentVersionRun_b0e3 {
  strings:
    $key_b0e3 = { e3 8c [2] c7 82 [2] ec ae [2] c2 8c [2] d6 97 [2] d9 8d [2] c7 90 [2] c5 91 [2] de 97 [2] c2 90 [2] de bf }

  condition:
    any of them
}