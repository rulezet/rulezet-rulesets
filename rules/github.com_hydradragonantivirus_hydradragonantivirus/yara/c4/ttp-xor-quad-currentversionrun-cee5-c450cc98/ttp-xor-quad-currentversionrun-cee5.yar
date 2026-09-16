rule TTP_XOR_QUAD_CurrentVersionRun_cee5 {
  strings:
    $key_cee5 = { 9d 8a [2] b9 84 [2] 92 a8 [2] bc 8a [2] a8 91 [2] a7 8b [2] b9 96 [2] bb 97 [2] a0 91 [2] bc 96 [2] a0 b9 }

  condition:
    any of them
}