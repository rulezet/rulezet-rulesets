rule TTP_XOR_QUAD_CurrentVersionRun_d20a {
  strings:
    $key_d20a = { 81 65 [2] a5 6b [2] 8e 47 [2] a0 65 [2] b4 7e [2] bb 64 [2] a5 79 [2] a7 78 [2] bc 7e [2] a0 79 [2] bc 56 }

  condition:
    any of them
}