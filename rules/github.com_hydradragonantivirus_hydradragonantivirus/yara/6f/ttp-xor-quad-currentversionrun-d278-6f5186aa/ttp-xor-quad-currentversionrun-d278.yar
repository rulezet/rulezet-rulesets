rule TTP_XOR_QUAD_CurrentVersionRun_d278 {
  strings:
    $key_d278 = { 81 17 [2] a5 19 [2] 8e 35 [2] a0 17 [2] b4 0c [2] bb 16 [2] a5 0b [2] a7 0a [2] bc 0c [2] a0 0b [2] bc 24 }

  condition:
    any of them
}