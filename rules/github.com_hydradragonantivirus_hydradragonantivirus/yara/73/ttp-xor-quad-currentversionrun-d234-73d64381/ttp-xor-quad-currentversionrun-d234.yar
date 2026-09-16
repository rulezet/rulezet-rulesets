rule TTP_XOR_QUAD_CurrentVersionRun_d234 {
  strings:
    $key_d234 = { 81 5b [2] a5 55 [2] 8e 79 [2] a0 5b [2] b4 40 [2] bb 5a [2] a5 47 [2] a7 46 [2] bc 40 [2] a0 47 [2] bc 68 }

  condition:
    any of them
}