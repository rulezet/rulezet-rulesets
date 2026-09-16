rule TTP_XOR_QUAD_CurrentVersionRun_cefa {
  strings:
    $key_cefa = { 9d 95 [2] b9 9b [2] 92 b7 [2] bc 95 [2] a8 8e [2] a7 94 [2] b9 89 [2] bb 88 [2] a0 8e [2] bc 89 [2] a0 a6 }

  condition:
    any of them
}